# SentinelLint

**Unified, local-first style enforcer & security linter for Python and C++.**

SIH 2026 · Problem Statement **USICT023** · Software Quality & Code Security

SentinelLint reads source code, builds a structural representation, runs deterministic style/quality/security rules, and reports actionable findings. It **does not execute submitted code** and the core analyzer requires **no network access or third-party runtime packages**.

## Current status

| Capability | Status |
|---|---|
| Python analysis | 25 rules · `ast` |
| C++ analysis | 17 rules · tokenizer + structural parser |
| Unified finding model | Built |
| Taint analysis | Built · intra-procedural + bounded same-file call flow |
| CWE + severity + confidence | Built |
| Auto-fix | Built · 5 validated fix rules |
| Reports | CLI · JSON · HTML · SARIF 2.1.0 |
| Baseline / ignore / suppression | Built |
| CI | GitHub Actions + `--fail-on` |
| Local dashboard | Built · browser UI on `127.0.0.1` |
| Validation | 34/34 annotated cases · 0 safe-corpus findings · 0 crashes |

## Quick start

Requires **Python 3.10+**.

```bash
cd SentinelLint
python run.py --selftest
```

Scan a file or project:

```bash
python run.py tests/vulnerable/example_vuln.py
python run.py tests/safe/example_safe.py
python run.py tests/vulnerable
python run.py tests/safe
```

Useful commands:

```bash
python run.py --rules
python run.py <path> --format json
python run.py <path> --format sarif -o results.sarif
python run.py <path> --format html -o report.html
python run.py <path> --severity HIGH
python run.py <path> --fail-on HIGH
python run.py <path> --write-baseline .sentinellint-baseline.json
python run.py <path> --baseline .sentinellint-baseline.json
python run.py <path> --fix
python run.py <path> --fix --write
```

## Local dashboard

The dashboard is a **local application**, not a hosted service.

```bash
python web_server.py
```

Open `http://127.0.0.1:8000`.

It supports source/project upload, code paste, finding filters, source context, evidence paths and fix/rescan workflow. The browser UI talks to the local Python server; the analyzer remains the source of truth.

The local workflow does not require internet access. GitHub Actions/SARIF upload is an **optional networked integration** for repositories that choose to use CI.

## Analysis pipeline

```text
Source
  ↓
Language detection
  ↓
Python AST / C++ structural parser
  ↓
Rule engine
  ↓
Taint/data-flow where applicable
  ↓
Finding
  ↓
Severity + confidence + CWE + evidence
  ↓
Remediation / validated fix
  ↓
Report, dashboard or CI
```

### Security rules covered

The 42-rule catalog covers, among other areas:

- code/command injection
- SQL injection
- SSRF
- hard-coded credentials
- insecure deserialization
- weak cryptography
- TLS verification issues
- path/archive traversal
- sensitive logging
- temporary-file and permission issues
- unsafe C/C++ memory operations
- use-after-free, double-free and null dereference
- uninitialized use and uncontrolled allocation sizes

Style and quality checks are included because the SIH problem combines code-style enforcement with security analysis.

Run `python run.py --rules` for the complete catalog, severity and CWE mapping.

## Taint analysis

SentinelLint can trace selected untrusted values from source to dangerous sink and expose the path as evidence. The current implementation is deliberately bounded:

- intra-procedural flow
- direct same-file function-call edges
- sink-context-aware sanitizers
- no full cross-file or return-value summary engine

The limitation is intentional: reported paths should be understandable and reproducible rather than pretending to provide compiler-grade global analysis.

## Fixes and CI

Auto-fixes use deterministic byte-range edits. A patched file is re-parsed before it is written; invalid patches are rejected. The fix system is **syntax/rule validated, not a proof of semantic equivalence**.

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | Scan completed without a policy violation |
| `1` | Completed scan violated the selected severity policy |
| `2` | Analysis/configuration error or partial scan |

`--baseline` hides findings already known to the project. `--fail-on` controls the CI threshold.

The included GitHub Actions workflow can generate SARIF and upload it to GitHub code scanning. GitHub supports SARIF 2.1.0 results from third-party analysis tools. citeturn435524search0turn435524search5

## Validation

The local regression gate is:

```bash
python run.py --selftest
python tests/test_hardening.py
```

Current measured corpus results:

- **42 rules** · 25 Python + 17 C++
- **34/34** annotated expected detections
- **0** false positives on the safe corpus
- **0** crashes on malformed input
- **2** findings with full source-to-sink evidence paths

These are **corpus-specific regression measurements**, not universal real-world accuracy claims. The test set includes safe counterparts, edge cases, malformed inputs and regression cases.

## Repository layout

```text
SentinelLint/
├── analyzer/
│   ├── core/       # findings, rules, policy, baseline, reports
│   ├── python/     # Python AST rules + taint
│   ├── cpp/        # C++ tokenizer/parser + rules
│   └── fixes/      # deterministic fixes
├── tests/          # vulnerable, safe, edge and hardening cases
├── web/            # local dashboard
├── run.py          # CLI entry point
├── web_server.py   # local dashboard server
└── .github/        # CI workflow
```

## What SentinelLint is — and is not

SentinelLint is a **lightweight, explainable, privacy-first SAST/linting project**. It is not intended to replace mature semantic platforms such as CodeQL, Semgrep or full compiler-based C++ analysis. CodeQL supports Python and modern C/C++ with deeper global data-flow and framework/library modeling; SentinelLint deliberately trades breadth and semantic depth for a small, inspectable, local workflow. citeturn435524search2

## References

- Python `ast`: https://docs.python.org/3/library/ast.html
- MITRE CWE: https://cwe.mitre.org/
- OWASP Top 10: https://owasp.org/Top10/
- SARIF: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
- GitHub code scanning / SARIF: https://docs.github.com/en/code-security/reference/code-scanning/sarif-files
- CodeQL: https://codeql.github.com/
- Bandit: https://bandit.readthedocs.io/
- Cppcheck: https://cppcheck.com/
- Semgrep: https://semgrep.dev/

## SIH demo

See **[DEMO.md](DEMO.md)** for the recommended live flow and judge questions.

See **[LOCAL_DASHBOARD.md](LOCAL_DASHBOARD.md)** for dashboard startup and troubleshooting.

See **[LIMITATIONS.md](LIMITATIONS.md)** for technical scope and honest comparison boundaries.
