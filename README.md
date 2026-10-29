# AI Log Analyzer

Local-first CI log investigation with optional AI explanations. Upload or paste a Jenkins console log to identify failure signatures, inspect line-numbered evidence, and request an explanation using only a bounded, redacted excerpt.

## Quick start

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
uv run uvicorn analyzer.app:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. The included synthetic linker example loads automatically. No API key is needed for local analysis.

Alternatively, create a Python virtual environment and run `pip install -e .`, then `uvicorn analyzer.app:app --host 127.0.0.1 --port 8000`.

## How it works

```text
UTF-8 build log (up to 5 MiB)
  -> strip ANSI codes and redact common secret formats
  -> extract error and warning signals
  -> classify using deterministic signatures
  -> select the primary failure and nearby lines
  -> bound context to 6,000 characters
  -> review context in the browser
  -> optionally send ONLY that context to OpenAI
```

The provider never receives the original log through the analysis endpoint. AI is a separate, explicit action. Local findings remain available if AI is disabled or fails.

### Example

```text
Failure Type
------------
Compilation Error

Relevant Error
--------------
undefined reference to init_driver

Likely Component
----------------
driver

Suggested Investigation
-----------------------
Check whether the required library was included during linking,
and verify symbol names and library order.
```

## Optional AI

Set `OPENAI_API_KEY` in the server process environment using your secret manager or terminal, then restart the server. Optionally set `OPENAI_MODEL` (default: `gpt-4o-mini`). The application does not load `.env` files automatically. Never commit credentials.

The separate **Generate explanation** button sends the displayed context to OpenAI's Chat Completions API. Requests have a 30-second timeout and responses are limited to 500 tokens. Provider usage can incur charges and is governed by the provider's data policies. The API key remains on the server. Automated tests mock the provider and do not require a key.

## CLI

```sh
uv run ai-log-analyzer examples/jenkins_console.log
uv run ai-log-analyzer examples/jenkins_console.log --json
```

The CLI is local-only. Exit code 0 means the log was analyzed, not that the build succeeded. Invalid input returns exit code 2. JSON reports contain redacted evidence and can still include sensitive information; review before sharing.

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /api/health` | Service status and AI availability |
| `POST /api/analyze` | JSON `{"log": "..."}`; local findings and bounded context |
| `POST /api/explain` | JSON `{"context": "L12: ..."}`; opt-in AI explanation |
| `GET /docs` | OpenAPI reference |

Logs must be non-empty UTF-8 text, at most 5 MiB. HTTP request bodies have a separate 6 MiB limit, including JSON escaping overhead. AI context is limited to 6,000 characters, not tokens. The browser never automatically requests an AI explanation.

## Classification and evidence

- Categories: compilation/linking, dependencies, tests, permissions, infrastructure, unclassified failure, warnings only, and no failure detected.
- Specific signatures take precedence over generic pipeline failure messages. Within the same rule, the first match wins. Across rules, the explicit rule order wins; it is a heuristic, not causal proof.
- The selected section contains up to three preceding and four following lines, plus additional diagnostic lines within the context budget. Line labels refer to the original log.
- At most 80 findings are returned. Counts include all recognized signals; omitted findings are reported.
- Component names are inferred from symbols, module names, or source paths. Unknown components are explicitly marked.
- The reduction metric compares excerpt characters (including line labels) with original log characters. It is not a token-cost estimate.

## Privacy and limitations

- No uploaded logs or reports are stored server-side. Logs exist in memory while processing; refreshing the browser clears the current input. Reports download only when requested.
- Common credentials, authorization headers, URL credentials, and PEM private keys are redacted before results are returned. Redaction is **best-effort**, not a guarantee: custom credentials, personal information, internal paths, and hostnames may remain. Always review context before sending it externally.
- Logs are untrusted data. AI instructions tell the model to treat evidence as data; this reduces but cannot eliminate prompt-injection risk. Nothing in a log or an AI response is executed. All log and AI text is rendered with `textContent`.
- Heuristics can misclassify quoted errors, recovered failures, unusual toolchains, and interleaved parallel stages. No failure detected is not proof of success. AI explanations are hypotheses, not verified fixes.
- The demo is intended for localhost. It has request-size limits and cross-origin POST protection, but no user authentication or distributed rate limiting. Before network deployment add authentication, TLS, per-user quotas, concurrency limits, and an approved data-handling policy.
- Fonts and Lucide icons load from external CDNs; these requests do not include log content. System fallback fonts and labeled primary actions remain usable offline. Self-host these assets for an isolated environment.

## Tests

```sh
uv run python -m unittest discover -s tests -v
```

Tests cover classification, secret redaction, bounded context, line-number preservation, input and transport limits, cross-origin rejection, static UI serving, and the mocked AI request boundary. GitHub Actions runs tests on Python 3.11, 3.12, and 3.13.

## Structure

```text
analyzer/core.py       extraction, classification, redaction, context selection
analyzer/ai.py         bounded provider integration
analyzer/app.py        FastAPI routes and request guards
analyzer/cli.py        local-only command-line interface
analyzer/static/       browser interface (plain HTML, CSS, JavaScript)
examples/              synthetic logs only
tests/                 local and API regression tests
```

This is a portfolio demonstration using synthetic examples, not evidence of deployment in a production CI environment.