import re
from dataclasses import asdict, dataclass

MAX_LOG_BYTES = 5 * 1024 * 1024
MAX_CONTEXT_CHARS = 6000
MAX_FINDINGS = 80
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SIGNAL = re.compile(
    r"\b(error|fatal|exception|warning|failed|failure|timeout|timed out)\b"
    r"|undefined reference|cannot find|permission denied|no space left|killed|OOMKilled",
    re.IGNORECASE,
)
BENIGN = re.compile(r"\b(?:0|no) (?:errors?|failures?|warnings?)\b", re.IGNORECASE)
RULES = (
    (
        "Compilation Error",
        r"undefined reference|unresolved external|ld: .*cannot find|linker command failed",
        "Check whether the required library was included during linking, and verify symbol names and library order.",
    ),
    (
        "Dependency Error",
        r"modulenotfounderror|no module named|could not resolve dependenc|could not find.*(?:package|artifact)|npm ERR!.*(?:E404|ERESOLVE)|no matching distribution",
        "Verify the dependency version, package registry access, and lockfile against the build environment.",
    ),
    (
        "Test Failure",
        r"assertionerror|assert.*failed|FAILED\s+\S*test|\btests? failed\b|\bfailures: [1-9]",
        "Reproduce the failing test with the same inputs and inspect its assertion and stack trace.",
    ),
    (
        "Permission Error",
        r"permission denied|access denied|unauthorized|forbidden|authentication failed",
        "Check the build identity's permissions and credential validity without printing credentials.",
    ),
    (
        "Infrastructure Error",
        r"no space left|out of memory|oomkilled|cannot allocate memory|connection refused|connection reset|timed out|timeout|could not resolve host|disk quota",
        "Inspect agent resource usage, network connectivity, service health, and configured timeouts.",
    ),
    (
        "Compilation Error",
        r"fatal error:|syntaxerror:|compilation (?:failed|error)|cannot find symbol|(?:\.(?:c|cpp|cc|h|java|ts):\d+.*|collect2: )\berror:",
        "Inspect the first compiler diagnostic, include paths, and recent source changes.",
    ),
)


@dataclass(frozen=True)
class Finding:
    line: int
    severity: str
    text: str


def redact(text: str) -> str:
    text = re.sub(
        r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|\Z)",
        lambda match: "[REDACTED PRIVATE KEY]" + "\n" * match.group(0).count("\n"),
        text,
        flags=re.DOTALL,
    )
    text = re.sub(
        r"(?i)(\b(?:authorization\s*[:=]\s*)?(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)(\b(?:[\w-]*(?:password|passwd|secret|token|api[_-]?key)|credential)\b[\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(r"(https?://)[^\s/@:]+:[^\s/@]+@", r"\1[REDACTED]@", text)
    text = re.sub(
        r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{20,})\b",
        "[REDACTED]",
        text,
    )
    return text


def infer_component(text: str) -> str:
    symbol = re.search(
        r"(?:undefined reference to|unresolved external symbol)\s+[`'\"]?([\w:]+)",
        text,
        re.IGNORECASE,
    )
    if symbol:
        return (
            symbol.group(1).split("::")[0].removeprefix("init_").removesuffix("_init")
        )
    module = re.search(r"No module named ['\"]([^'\"]+)", text)
    if module:
        return module.group(1)
    source = re.search(
        r"(?:^|[\s(])([\w./\\-]+\.(?:cpp|cc|c|h|py|java|ts|js))(?::\d+)?", text
    )
    return source.group(1) if source else "Unknown"


def analyze(text: str) -> dict:
    if not text.strip():
        raise ValueError("The log is empty. Paste or upload a non-empty text log.")
    if len(text.encode("utf-8")) > MAX_LOG_BYTES:
        raise ValueError("The log exceeds the 5 MiB limit.")
    if "\x00" in text:
        raise ValueError("Binary files are not supported. Use a UTF-8 text log.")

    raw_lines = ANSI.sub("", text).splitlines()
    lines = redact("\n".join(raw_lines)).splitlines()
    findings = []
    candidates = []
    error_count = 0
    warning_count = 0
    for index, line in enumerate(lines):
        searchable = BENIGN.sub("", line)
        if not SIGNAL.search(searchable) and not any(
            re.search(rule[1], searchable, re.IGNORECASE) for rule in RULES
        ):
            continue
        severity = (
            "warning"
            if re.search(r"\bwarning\b", searchable, re.IGNORECASE)
            and not re.search(
                r"\b(error|fatal|failed|exception)\b", searchable, re.IGNORECASE
            )
            else "error"
        )
        if severity == "warning":
            warning_count += 1
        else:
            error_count += 1
        finding = Finding(index + 1, severity, line[:1000])
        findings.append(finding)
        if severity == "error":
            for priority, (category, pattern, investigation) in enumerate(RULES):
                if re.search(pattern, searchable, re.IGNORECASE):
                    candidates.append((priority, index, category, investigation))
                    break

    if candidates:
        _, focus, category, investigation = min(candidates)
        confidence = "Rule match"
    elif error_count:
        focus = next(
            finding.line - 1 for finding in findings if finding.severity == "error"
        )
        category = "Unclassified Failure"
        investigation = "Inspect the surrounding failure output and the preceding pipeline stage. No known signature matched."
        confidence = "Needs review"
    else:
        focus = findings[0].line - 1 if findings else 0
        category = "Warnings Only" if warning_count else "No Failure Detected"
        investigation = (
            "Review the warnings; no recognized failure was found."
            if warning_count
            else "No known failure signature was found. Check the build exit code before treating this as success."
        )
        confidence = "No error signature"

    primary = lines[focus][:1000] if findings else "No recognized error or warning."
    selected = set()
    if findings:
        selected.update(range(max(0, focus - 3), min(len(lines), focus + 5)))
    for finding in findings:
        if len(selected) >= 60:
            break
        selected.add(finding.line - 1)
    focused = sorted(selected, key=lambda index: (abs(index - focus), index))
    chunks = {}
    budget = MAX_CONTEXT_CHARS
    for index in focused:
        chunk = f"L{index + 1}: {lines[index][:1000]}\n"
        if len(chunk) <= budget:
            chunks[index] = chunk
            budget -= len(chunk)
    context = "".join(chunks[index] for index in sorted(chunks))
    visible = sorted(
        findings, key=lambda finding: (abs(finding.line - 1 - focus), finding.line)
    )[:MAX_FINDINGS]
    visible.sort(key=lambda finding: finding.line)
    return {
        "failure_type": category,
        "relevant_error": primary,
        "likely_component": infer_component(primary),
        "suggested_investigation": investigation,
        "confidence": confidence,
        "failure_line": focus + 1 if findings else None,
        "findings": [asdict(finding) for finding in visible],
        "context": context,
        "stats": {
            "total_lines": len(raw_lines),
            "errors": error_count,
            "warnings": warning_count,
            "findings_omitted": max(0, len(findings) - MAX_FINDINGS),
            "original_chars": len(text),
            "context_chars": len(context),
            "reduction_percent": round(max(0, 1 - len(context) / len(text)) * 100, 1),
        },
    }
