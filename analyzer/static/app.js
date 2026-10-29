const element = (id) => document.getElementById(id);
const samples = {
  linker: "Started by upstream project driver-ci\n[Pipeline] Start of Pipeline\n[Pipeline] stage (Checkout)\nChecking out revision 3a7b12f\n[Pipeline] stage (Build)\n+ cmake --build build --parallel 4\n[ 25%] Building C object src/driver.c.o\n[ 50%] Building C object src/main.c.o\nsrc/driver.c:42: warning: unused variable 'status'\n[ 75%] Linking C executable driver_test\n/usr/bin/ld: main.c:(.text+0x24): undefined reference to `init_driver'\ncollect2: error: ld returned 1 exit status\nmake[2]: *** [driver_test] Error 1\nmake[1]: *** [all] Error 2\n[Pipeline] End of Pipeline\nERROR: script returned exit code 2\nFinished: FAILURE",
  test: "[Pipeline] stage (Test)\n+ pytest tests/ -q\ncollected 24 items\ntests/test_config.py ....\ntests/test_driver.py ...F\nFAILED tests/test_driver.py::test_init - AssertionError: expected 0, got 1\n23 passed, 1 failed in 2.14s\nFinished: FAILURE",
  dependency: "[Pipeline] stage (Install)\n+ python build.py\nTraceback (most recent call last):\n  File \"build.py\", line 3, in <module>\n    import requests\nModuleNotFoundError: No module named 'requests'\nERROR: script returned exit code 1\nFinished: FAILURE"
};
let report = null;
let aiEnabled = false;
let revision = 0;
let busy = false;
const log = element("log");

function icons() {
  if (window.lucide) window.lucide.createIcons();
}

function invalidate() {
  revision += 1;
  report = null;
  element("results").hidden = true;
  element("empty").hidden = false;
  element("download").disabled = true;
  element("explain").disabled = true;
  element("status").textContent = "";
  element("line-count").textContent = `${log.value ? log.value.split(/\r?\n/).length : 0} lines`;
}

function status(message, error = false) {
  element("status").textContent = message;
  element("status").classList.toggle("error", error);
}

async function post(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Invalid request. Check the log size and format.");
  return data;
}

function render(result) {
  element("empty").hidden = true;
  element("results").hidden = false;
  element("failure-type").textContent = result.failure_type;
  element("confidence").textContent = result.confidence;
  element("confidence").classList.toggle("neutral", result.stats.errors === 0);
  element("failure-line").textContent = result.failure_line ? `PRIMARY SIGNAL / LINE ${result.failure_line}` : "NO RECOGNIZED FAILURE SIGNATURE";
  element("metric-lines").textContent = result.stats.total_lines.toLocaleString();
  element("metric-errors").textContent = result.stats.errors.toLocaleString();
  element("metric-warnings").textContent = result.stats.warnings.toLocaleString();
  element("metric-reduction").textContent = `${result.stats.reduction_percent}%`;
  element("relevant-error").textContent = result.relevant_error;
  element("component").textContent = result.likely_component;
  element("investigation").textContent = result.suggested_investigation;
  element("context").textContent = result.context || "No evidence selected.";
  element("context-size").textContent = `${result.stats.context_chars.toLocaleString()} / 6,000 characters`;
  element("evidence-count").textContent = `${result.findings.length} shown${result.stats.findings_omitted ? ` / ${result.stats.findings_omitted} omitted` : ""}`;
  element("evidence").replaceChildren();
  for (const finding of result.findings) {
    const row = document.createElement("tr");
    for (const [index, value] of [finding.line, finding.severity, finding.text].entries()) {
      const cell = document.createElement("td");
      cell.textContent = value;
      if (index === 1) cell.className = `level-${finding.severity}`;
      row.append(cell);
    }
    element("evidence").append(row);
  }
  element("explanation").hidden = true;
  element("explanation").textContent = "";
  element("ai-message").textContent = aiEnabled ? "" : "OPENAI_API_KEY is not configured on the server.";
  element("explain").disabled = !aiEnabled || !result.context;
  element("download").disabled = false;
}

async function runAnalysis() {
  if (busy) return;
  if (!log.value.trim()) return status("Paste or upload a non-empty log.", true);
  if (new TextEncoder().encode(log.value).length > 5 * 1024 * 1024) return status("The log exceeds the 5 MiB limit.", true);
  const currentRevision = revision;
  busy = true;
  element("analyze").disabled = true;
  element("analyze").querySelector("span").textContent = "Analyzing...";
  status("Analyzing locally...");
  try {
    const result = await post("/api/analyze", {
      log: log.value
    });
    if (revision !== currentRevision) return;
    report = result;
    render(result);
    status("Analysis complete. No data sent to AI.");
  } catch (error) {
    if (revision === currentRevision) status(error.message, true);
  } finally {
    busy = false;
    element("analyze").disabled = false;
    element("analyze").querySelector("span").textContent = "Analyze log";
  }
}

async function loadFile(file) {
  if (!file) return;
  if (file.size > 5 * 1024 * 1024) return status("The file exceeds the 5 MiB limit.", true);
  const currentRevision = ++revision;
  try {
    const text = new TextDecoder("utf-8", {
      fatal: true
    }).decode(await file.arrayBuffer());
    if (revision !== currentRevision) return;
    if (text.includes("\0")) throw new Error("Binary files are not supported.");
    log.value = text;
    element("filename").textContent = file.name;
    invalidate();
    status("Log loaded.");
  } catch (error) {
    if (revision === currentRevision) status(`Cannot read file as UTF-8 text: ${error.message}`, true);
  }
}

element("analyze").addEventListener("click", runAnalysis);
log.addEventListener("input", invalidate);
element("clear").addEventListener("click", () => {
  log.value = "";
  element("file").value = "";
  element("filename").textContent = "Untitled log";
  invalidate();
  log.focus();
});
element("sample").addEventListener("change", () => {
  log.value = samples[element("sample").value];
  element("filename").textContent = "jenkins_console.log";
  invalidate();
  runAnalysis();
});
element("file").addEventListener("change", (event) => loadFile(event.target.files[0]));
for (const name of ["dragenter", "dragover"]) element("drop-zone").addEventListener(name, (event) => {
  event.preventDefault();
  element("drop-zone").classList.add("dragging");
});
for (const name of ["dragleave", "drop"]) element("drop-zone").addEventListener(name, (event) => {
  event.preventDefault();
  element("drop-zone").classList.remove("dragging");
  if (name === "drop") loadFile(event.dataTransfer.files[0]);
});
element("download").addEventListener("click", () => {
  if (!report) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], {
    type: "application/json"
  }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "analysis-report.json";
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
element("explain").addEventListener("click", async () => {
  if (!report || !aiEnabled) return;
  const currentReport = report;
  element("explain").disabled = true;
  element("ai-message").textContent = "Requesting explanation from OpenAI...";
  try {
    const data = await post("/api/explain", {
      context: currentReport.context
    });
    if (report !== currentReport) return;
    currentReport.ai_explanation = data.explanation;
    element("explanation").textContent = data.explanation;
    element("explanation").hidden = false;
    element("ai-message").textContent = "AI-generated hypothesis. Verify against your build environment.";
  } catch (error) {
    if (report === currentReport) element("ai-message").textContent = error.message;
  } finally {
    if (report === currentReport) element("explain").disabled = false;
  }
});

async function initialize() {
  icons();
  log.value = samples.linker;
  invalidate();
  try {
    const response = await fetch("/api/health");
    if (!response.ok) throw new Error("Server unavailable");
    const health = await response.json();
    aiEnabled = health.ai_enabled;
    element("ai-state").textContent = aiEnabled ? "Available / opt-in" : "Not configured";
  } catch {
    element("ai-state").textContent = "Unavailable";
  }
  runAnalysis();
}
initialize();