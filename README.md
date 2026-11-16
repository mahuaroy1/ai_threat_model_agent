# AI Threat Model Agent

Static threat modeling for **LangChain / LangGraph** applications. The agent reads an
application's Python code and configuration, maps its AI attack surface, and writes a
threat model in which every item points to a concrete file and line:

- **Entry points:** FastAPI/Flask routes, LangServe, the LangGraph Platform (`langgraph.json`), Streamlit, Gradio, Chainlit, CLI.
- **Model calls:** the provider, and whether the model is local or hosted.
- **Agents and tools:** what each tool can do (shell, SQL, files, network, and so on).
- **Retrieval sources:** web loaders, search tools, vector stores, databases.
- **Memory:** checkpointers, long-term stores, and chat histories.
- **Remote agents and MCP servers:** `MultiServerMCPClient`, `mcp` clients, `mcp.json`, `RemoteGraph`, A2A clients.
- **Trust boundaries and data flows**, drawn as a Mermaid diagram.
- **Findings** mapped to the OWASP Top 10 for LLM Applications (2025) **and** the
  OWASP Top 10 for Agentic Applications (ASI01-ASI10).
- **Agent controls checklist:** which defenses (human approval, limits, guardrails,
  sandboxing, memory isolation, and so on) have code evidence, and which are missing.

The scanned code is **never executed or imported**; analysis uses Python's `ast` module.
An optional local **Ollama Qwen** model writes an advisory executive summary from the
redacted findings.

## License

All rights are reserved. No permission is granted to copy, modify, distribute, or
otherwise use this project without prior written permission from the copyright
holder(s), except for rights that cannot be restricted by applicable law.

## Install

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows  (Linux/macOS: source .venv/bin/activate)
pip install -e .[dev]           # the scanner itself has no runtime dependencies
```

Requires Python 3.10+.

## Usage

```bash
ai-threat-model path/to/app                                   # Markdown + JSON in ./threat-model-report
ai-threat-model path/to/app -f md json sarif -o reports       # add SARIF for GitHub code scanning
ai-threat-model path/to/app --fail-on high                    # CI gate: exit 1 on high/critical
python -m ai_threat_model path/to/app --log-file scan.log     # rotating log file (secrets masked)
ai-threat-model path/to/app --cache-dir .ai-threat-model-cache  # incremental: reuse unchanged files
```

### Incremental analysis (cache)

`--cache-dir DIR` saves the intermediate representation after each scan and
reuses it on the next one:

| Saved per file | Used for |
|---|---|
| SHA-256 of the content | Detecting changed files |
| Converged function summaries (parameters → sinks, return labels) | Seeding interprocedural analysis without re-parsing the file |
| Dependencies: the files whose summaries it used (the cross-file call graph) | Re-analyzing every caller of a changed file |
| Components, findings, frameworks, approval points | Rebuilding the threat model without re-analysis |

A file is reused only if its content and everything it depends on are unchanged.
If any function is added, removed, renamed, or changes its parameters, import
resolution may change, so every Python file is re-analyzed. Correlation (trust
boundaries, data flows, cross-component risks) always runs because it is cheap.
An incremental scan produces the same report as a full scan; the tests check this.

- `--rebuild-cache` ignores the existing cache and writes a fresh one.
- The cache is JSON, never pickle, and is validated on load. A corrupt,
  oversized, or other-version cache is ignored with a warning, and a full scan runs.
- Anyone who can edit the cache can hide findings. Don't restore caches from
  untrusted sources, such as CI caches written by forked pull requests.
- The final graph (components, trust boundaries, data flows, findings) is always
  saved in `threat-model.json`.

### Optional AI narrative with Ollama + Qwen

```bash
ollama pull qwen2.5-coder:7b
ai-threat-model path/to/app --llm
ai-threat-model path/to/app --llm --ollama-model qwen2.5:7b --ollama-timeout 180 --ollama-retries 2
```

The narrative is a separate, advisory LLM-generated summary—not a scanner finding
or a validation of the findings. The static analysis produces the report's
evidence-backed findings; LLM summaries can omit, misstate, or overstate impact.
Verify every narrative claim against the cited source and finding evidence before
relying on it.

| Option | Default | Meaning |
|---|---|---|
| `--ollama-url` | `http://127.0.0.1:11434` | Must be loopback unless `--allow-remote-llm` |
| `--ollama-model` | `qwen2.5-coder:7b` | Any model you have pulled |
| `--ollama-timeout` | `300` s | Inactivity timeout: longest wait for the first token or between tokens. Responses are streamed, so long answers do not time out; raise it if prompt processing is slow on CPU |
| `--ollama-retries` | `2` (max 5) | Retries after transient errors (connection, timeout, 408/429/5xx), with linear backoff |

If Ollama is unavailable, the scan still completes. The report then notes
"AI narrative skipped: ...".

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed; no finding met `--fail-on` |
| 1 | At least one finding met `--fail-on` |
| 2 | Usage, scan, report, or LLM configuration error |

## Examples

| Path | What it is |
|---|---|
| [examples/vulnerable_support_agent](examples/vulnerable_support_agent) | An **intentionally vulnerable** FastAPI + LangGraph support agent, used as a scan target. Each weakness is annotated with the rule that finds it. Do not run it. |
| [examples/secure_support_agent](examples/secure_support_agent) | A hardened, **runnable** console agent on a local Qwen model in Ollama |
| [examples/run_demo.py](examples/run_demo.py) | Scans an example, asks Ollama Qwen for a narrative, and writes all report formats |
| [examples/sample-reports](examples/sample-reports) | Sanitized static-analysis reports for the vulnerable example; the scanned app was not run and no Ollama narrative is included |

```bash
# Scan + Ollama narrative demo (no install needed)
python examples/run_demo.py
python examples/run_demo.py --target examples/secure_support_agent

# Real LangChain app that calls Ollama
pip install -r examples/secure_support_agent/requirements.txt
python examples/secure_support_agent/support_cli.py
```

The secure example pins `langchain-core`, `langchain-ollama`, and `langgraph`. If pip
cannot resolve these versions on your Python, update the pins to the current releases.

## Rules

| ID | Risk | OWASP LLM 2025 | OWASP Agentic |
|---|---|---|---|
| AITM-PI-001 | Untrusted input concatenated into a prompt | LLM01 Prompt Injection | ASI01 |
| AITM-PI-002 | Untrusted data controls a system prompt or template | LLM01 | ASI01 |
| AITM-PI-003 | Indirect prompt injection: external content plus privileged tools | LLM01 | ASI01, ASI06 |
| AITM-PI-004 | Jinja2 prompt template | LLM01 | ASI01, ASI05 |
| AITM-TOOL-001 | High-risk built-in tool (ShellTool, Python REPL, Requests, file management) | LLM06 Excessive Agency | ASI02, ASI05 |
| AITM-TOOL-002 | Custom tool performs a privileged operation | LLM06 | ASI02 |
| AITM-TOOL-003 | Model-controlled tool argument reaches a dangerous sink | LLM06 | ASI02, ASI05 |
| AITM-TOOL-004 | Framework safety guard disabled (`allow_dangerous_code=True`, ...) | LLM06 | ASI02, ASI05 |
| AITM-TOOL-005 | No human approval before side-effecting tools | LLM06 | ASI02, ASI09 |
| AITM-TOOL-006 | Unbounded agent loop (`max_iterations=None`, `recursion_limit` >= 1000) | LLM10 Unbounded Consumption | ASI08, ASI10 |
| AITM-OUT-001 | Model output reaches eval, shell, SQL, files, or network | LLM05 Improper Output Handling | ASI05, ASI02 |
| AITM-OUT-002 | Model output rendered as trusted HTML | LLM05 | ASI09 |
| AITM-INJ-001 | User input reaches a dangerous sink | LLM05 | ASI05 |
| AITM-DATA-001 | Hard-coded secret (code or config) | LLM02 Sensitive Information Disclosure | ASI03 |
| AITM-DATA-002 | Secret or personal data sent to a model | LLM02 | - |
| AITM-DATA-003 | Sensitive data in logs, or debug/verbose mode | LLM02 | - |
| AITM-DATA-004 | Prompts exported to a tracing vendor | LLM02 | - |
| AITM-DATA-005 | Credential embedded in a system prompt | LLM07 System Prompt Leakage | ASI03 |
| AITM-AUTH-001 | LLM HTTP entry point without detected authentication | LLM10 | ASI03 |
| AITM-SUP-001 | Unpinned AI framework dependency | LLM03 Supply Chain | ASI04 |
| AITM-SUP-002 | Unpinned Prompt Hub prompt or MCP server package (`npx`/`uvx` without a version) | LLM03 | ASI04 |
| AITM-MEM-001 | Untrusted data (tool arguments, model output, web content) written to persistent memory | LLM04 Data and Model Poisoning | ASI06 |
| AITM-MEM-002 | Memory scope (`thread_id`, store namespace) chosen by the caller or model | LLM02 | ASI06, ASI03 |
| AITM-ID-001 | Tool lets the model choose a user/object ID with no caller identity (confused deputy, IDOR) | LLM06 | ASI03, ASI02 |
| AITM-MA-001 | Remote agent / MCP channel over plaintext HTTP or without credentials | LLM06 | ASI07, ASI04 |
| AITM-MA-002 | Multi-agent delegation reaches privileged tools | LLM06 | ASI07, ASI08, ASI10 |

### OWASP Top 10 for Agentic Applications

Each report contains an ASI coverage table: every risk with its finding count, the rules
that fired, and the related controls. Static analysis covers the agentic risks
unevenly, so the report lists them all, including those with no findings:

| Risk | Static coverage |
|---|---|
| ASI01 Agent Goal Hijack | Good: prompt-injection sources reaching prompts, plus external content combined with privileged tools |
| ASI02 Tool Misuse | Good: dangerous tools, taint into sinks, missing approval |
| ASI03 Identity and Privilege Abuse | Partial: unauthenticated entry points, model-chosen IDs, embedded credentials. Real authorization logic (IDOR) needs runtime tests |
| ASI04 Supply Chain | Good: unpinned packages, hub prompts, MCP launchers |
| ASI05 Unexpected Code Execution | Good: eval/exec/shell/import sinks, Python REPL tools |
| ASI06 Memory and Context Poisoning | Partial: untrusted memory writes, caller-chosen memory scope |
| ASI07 Insecure Inter-Agent Communication | Partial: transport and credentials of MCP/A2A/RemoteGraph channels, delegation to privileged agents |
| ASI08 Cascading Failures | Limited: loop limits and rate limits only |
| ASI09 Human-Agent Trust Exploitation | Limited: approval gates and unescaped output |
| ASI10 Rogue Agents | Limited: loop bounds and audit trail. Rogue behavior is a runtime property |

### Agent controls checklist

The checklist reports **evidence** that a defense exists (`present`), no violation found
but the defense cannot be confirmed (`partial`), `missing`, or `n/a` when no matching
components exist. "Present" means the code references the control, not that the control
is effective.

| ID | Control | OWASP | Evidence looked for |
|---|---|---|---|
| CTRL-01 | Human approval before side-effecting actions | ASI02, ASI09 | `interrupt`, `interrupt_before`, HITL middleware |
| CTRL-02 | Bounded agent execution | ASI08, ASI10 | `recursion_limit`, `max_iterations`, `max_execution_time` |
| CTRL-03 | Authenticated entry points | ASI03 | Auth dependencies and decorators on HTTP routes |
| CTRL-04 | Caller identity enforced inside tools | ASI03, ASI02 | `InjectedToolArg`, `InjectedState`, `RunnableConfig` parameters |
| CTRL-05 | Rate limiting and usage quotas | ASI08 | `InMemoryRateLimiter`, slowapi, flask-limiter |
| CTRL-06 | Audit trail of agent actions | ASI09, ASI10 | Callbacks, LangSmith, Langfuse, OpenTelemetry |
| CTRL-07 | Prompt-injection and content guardrails | ASI01 | NeMo Guardrails, LLM Guard, Presidio, moderation |
| CTRL-08 | Structured, validated model output | ASI05, ASI02 | `with_structured_output`, Pydantic/JSON output parsers |
| CTRL-09 | Sandboxed code execution | ASI05 | e2b, langchain-sandbox, Docker, Modal |
| CTRL-10 | Pinned agent supply chain | ASI04 | Absence of SUP-001 and SUP-002 |
| CTRL-11 | Secured inter-agent and MCP channels | ASI07 | Absence of MA-001 and MA-002 |
| CTRL-12 | Memory isolation and write validation | ASI06 | Absence of MEM-001 and MEM-002 |

## How it works

```
discovery -> parse all .py files -> interprocedural summaries -> per-file analysis -> config analysis
          -> correlation (trust boundaries, data flows, cross-component risks) -> reports (+ optional LLM narrative)
```

| Module | Responsibility |
|---|---|
| `discovery.py` | Bounded file walk: no symlinks, skips vendored folders, enforces size and count limits |
| `python_analyzer.py` | AST inventory plus taint tracking (user input, model output, tool arguments, secrets, PII) |
| `interprocedural.py` | Function summaries: which parameters reach which sinks, and what each function returns |
| `cache.py` | Validated JSON cache of summaries, dependencies, and per-file results for incremental scans |
| `config_analyzer.py` | `.env`/YAML/JSON secrets, LangSmith tracing, `langgraph.json`, MCP server configs, dependency pinning |
| `agentic.py` | Shared checks for agent channels (TLS, credentials) and version pinning of MCP packages and hub prompts |
| `correlation.py` | Trust boundaries, data flows, PI-003, TOOL-005, AUTH-001, MA-002, agent controls checklist |
| `catalog.py`, `rules.py`, `sensitive.py` | Knowledge base: frameworks, sinks, rules, secret/PII patterns |
| `reporting.py` | Markdown (with Mermaid), JSON, and SARIF 2.1.0 output, written atomically |
| `ollama_client.py`, `narrative.py` | Hardened local LLM client, prompt construction, and output sanitization |
| `cli.py`, `logging_setup.py` | Command-line interface and redacting, rotating logs |

**Interprocedural analysis.** The analyzer first summarizes every project function:
which parameters reach which sinks, and which parameters flow to the return value.
It repeats this until the summaries stop changing. A `@tool` that passes its argument
to a helper in another module, which then calls `subprocess.run(..., shell=True)`, is
reported at the tool's call site. The finding includes the helper's sink as a related
location. Relative imports and `self.method()` calls are resolved.

## Security design

- The target is never executed or imported. Parsing is the only operation on its code.
- Secrets are masked (`sk-p…[REDACTED]`) in findings, reports, LLM prompts, and logs.
- The LLM is **loopback-only** by default. The client ignores proxy environment
  variables, caps response size, and streams responses with an inactivity timeout, caps output tokens, and uses bounded retries.
- Prompt-injection resistance: scan facts are fenced in `<scan_data>` as untrusted data,
  and the LLM's answer is stripped of control characters, HTML-escaped, redacted, and
  length-capped.
- Report text is escaped for Markdown tables and Mermaid. Files are written atomically.
- One unparseable or hostile file is recorded as a warning; it does not abort the scan.

## Limitations

- Static and heuristic. Dynamic dispatch, decorators that wrap functions, and data
  passed through containers or class attributes across files can be missed. Treat
  "no findings" as "nothing detected", not "secure".
- Authentication detection is best-effort (low confidence).
- Agentic risks that exist only at runtime cannot be proven statically. These include
  goal hijack during a live session, rogue or colluding agents, cascading failures, and
  object-level authorization bugs (IDOR). The scanner reports the preconditions and the
  missing controls. Confirm them with runtime red-teaming and authorization tests.
- Python LangChain/LangGraph only. Other frameworks are a planned extension through `catalog.py`.

## Tests

```bash
python -m unittest discover -s tests -t . -v
# or
python -m pytest
```

The tests use an in-process stub Ollama server on 127.0.0.1, so no model or network is needed.
