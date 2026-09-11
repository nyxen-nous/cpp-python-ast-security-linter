# SentinelLint — SIH Demo

The goal is one complete loop:

**Scan → Detect → Explain → Fix → Re-scan**

## 1. Start

```powershell
python web_server.py
```

Open `http://127.0.0.1:8000`.

Keep the terminal window open while the dashboard is running.

## 2. Vulnerable Python

Upload:

```text
`tests/vulnerable/example_vuln.py`
```

Expected result:

```text
15 findings
2 CRITICAL · 6 HIGH · 5 MEDIUM · 2 LOW
```

Open a finding and show:

- source line
- severity
- CWE
- confidence reason
- explanation
- remediation
- evidence path when available

## 3. Safe Python

Upload:

```text
`tests/safe/example_safe.py`
```

Expected result:

```text
0 findings
```

This demonstrates that the safe corpus is not simply “expected to fail”; the near-miss counterparts remain clean.

## 4. C++

Upload:

```text
`tests/vulnerable/example_vuln.cpp`
```

Expected result:

```text
9 findings
```

Then show `tests/safe/example_safe.cpp` for the clean counterpart.

## 5. Fix + re-scan

For a fixable Python finding:

```text
Preview fix
   ↓
Apply fix
   ↓
Re-parse
   ↓
Re-scan
   ↓
Resolved finding
```

The fix system is deterministic and rejects a patch that fails the re-parse check.

## 6. CLI backup

If the dashboard is unavailable:

```powershell
python run.py tests/vulnerable/example_vuln.py
python run.py tests/safe/example_safe.py
python run.py --selftest
```

## 7. Good judge answers

**Why AST instead of grep?**

AST/structural analysis lets rules inspect actual code constructs instead of matching words inside comments and strings.

**How is taint different from a pattern rule?**

The analyzer can mark selected inputs as untrusted, follow supported assignments/call edges, and show the source-to-sink path when a dangerous operation is reached.

**Why not CodeQL?**

We are not claiming to replace it. SentinelLint is intentionally lightweight, local-first and explainable, with a small dependency-free workflow. CodeQL is substantially deeper and broader. citeturn435524search2

**Is the 100% precision/recall number real-world accuracy?**

No. It is measured on our 34-case annotated validation corpus and its safe counterparts.

**Does the analyzer execute submitted code?**

No. It only reads source. The submitted program is never executed.

**Can it work without internet?**

Yes for the local core and dashboard. GitHub/SARIF upload through CI is an optional networked workflow.
