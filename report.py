"""
Report output.

One unified finding model in, four formats out. Nothing here knows or cares
whether a finding came from the Python analyzer or the C++ analyzer, which
is the whole point of freezing the Finding schema.
"""

import html
import json
import os

from .finding import SEVERITY_ORDER
from .rule import all_rules

# ----------------------------------------------------------------- colours
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
COLOR = {
    "CRITICAL": "\033[95m",
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW": "\033[94m",
}


def _use_colour(force=None):
    if force is not None:
        return force
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(os.sys.stdout, "isatty") and os.sys.stdout.isatty()


# ═════════════════════════════════════════════════════════════════════ CLI
def render_cli(result, colour=None, show_taint=True):
    c = _use_colour(colour)

    def paint(text, code):
        return f"{code}{text}{RESET}" if c else text

    counts = result.counts
    lines = []
    bar = "=" * 74
    lines.append("")
    lines.append(bar)
    lines.append(f"  SentinelLint  |  {result.files_scanned} file(s) scanned"
                 f"  |  {result.duration:.2f}s")
    langs = ", ".join(f"{k}: {v}" for k, v in sorted(result.languages.items())) or "none"
    lines.append(f"  Languages: {langs}")
    total = len(result.findings)
    noun = "finding" if total == 1 else "findings"
    lines.append(f"  {total} {noun}   -   "
                 f"{counts['CRITICAL']} CRITICAL   {counts['HIGH']} HIGH   "
                 f"{counts['MEDIUM']} MEDIUM   {counts['LOW']} LOW")
    lines.append(bar)
    lines.append("")

    for w in result.warnings:
        lines.append(f"  ! {w}")
    for n in getattr(result, "notes", []):
        lines.append(f"  i {n}")
    if result.warnings or getattr(result, "notes", []):
        lines.append("")

    if not result.findings:
        if result.status == "PARTIAL":
            lines.append("  No findings were reported, but the scan is INCOMPLETE due to warnings above.")
            lines.append("  Do not interpret a partial scan as a clean result.")
        elif result.status == "ERROR":
            lines.append("  Scan could not complete.")
        else:
            lines.append("  No issues found. Analysis completed successfully.")
        lines.append("")
        return "\n".join(lines)

    current_file = None
    for f in result.sorted_findings():
        if f.file != current_file:
            current_file = f.file
            lines.append(paint(f"--- {f.file}", BOLD))
            lines.append("")

        sev = paint(f"[{f.severity}]", COLOR.get(f.severity, ""))
        lines.append(f"{sev} {f.rule_id}   line {f.line}   ({f.language})")
        lines.append(f"    Issue:       {f.message}")
        if f.cwe:
            lines.append(f"    CWE:         {f.cwe}")
        lines.append(f"    Confidence:  {f.confidence}  -  {f.confidence_reason}")
        if f.snippet:
            lines.append(f"    Code:        {f.snippet}")
        if f.explanation:
            lines.append(f"    Why:         {_wrap(f.explanation)}")
        if f.remediation:
            lines.append(f"    Fix:         {_wrap(f.remediation)}")

        if show_taint and f.taint_path:
            lines.append(paint("    Evidence:    untrusted input reaches this call", BOLD))
            for s in f.taint_path:
                arrow = {"source": "[source]", "propagate": "[flows] ", "call": "[call]   ", "sink": "[sink]  "}.get(s.kind, "")
                lines.append(f"                 line {s.line:<4} {arrow} {s.description}")
        if f.fixable and f.fix is not None:
            lines.append(f"    Auto-fix:    available  -  {f.fix.describe}")
        lines.append("")

    fixable = sum(1 for f in result.findings if f.fixable and f.fix)
    if fixable:
        lines.append(f"  {fixable} finding(s) can be fixed automatically:  "
                     f"run again with  --fix  to preview,  --fix --write  to apply.")
        lines.append("")
    return "\n".join(lines)


def _wrap(text, width=88, indent=" " * 17):
    words, out, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            out.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        out.append(cur)
    return ("\n" + indent).join(out)


# ════════════════════════════════════════════════════════════════════ JSON
def render_json(result, indent=2):
    return json.dumps(result.to_dict(), indent=indent)


# ═══════════════════════════════════════════════════════════════════ SARIF
SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error",
               "MEDIUM": "warning", "LOW": "note"}


def render_sarif(result, indent=2):
    """SARIF 2.1.0 - the interchange format GitHub Code Scanning consumes."""
    used = {}
    for f in result.findings:
        used.setdefault(f.rule_id, f)

    rules = []
    for rid, f in sorted(used.items()):
        tags = [f.language, f.category]
        if f.cwe:
            tags.append(f.cwe)
        rules.append({
            "id": rid,
            "name": rid.replace(".", ""),
            "shortDescription": {"text": f.message},
            "fullDescription": {"text": f.explanation or f.message},
            "help": {"text": f.remediation or "", "markdown": f"**Fix:** {f.remediation}"},
            "defaultConfiguration": {"level": SARIF_LEVEL.get(f.severity, "warning")},
            "properties": {"tags": tags, "security-severity": _sec_score(f.severity)},
        })

    results = []
    for f in result.sorted_findings():
        entry = {
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.message} ({f.confidence} confidence: {f.confidence_reason})"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file.replace(os.sep, "/")},
                    "region": {
                        "startLine": f.line,
                        "startColumn": max(1, f.col + 1),
                        "endLine": f.end_line or f.line,
                        **({"snippet": {"text": f.snippet}} if f.snippet else {}),
                    },
                }
            }],
            "properties": {"confidence": f.confidence, "category": f.category},
        }
        if f.taint_path:
            entry["codeFlows"] = [{
                "threadFlows": [{
                    "locations": [{
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.file.replace(os.sep, "/")},
                                "region": {"startLine": s.line},
                            },
                            "message": {"text": s.description},
                        }
                    } for s in f.taint_path]
                }]
            }]
        results.append(entry)

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "SentinelLint",
                "version": "1.0",
                "informationUri": "https://github.com/",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=indent)


def _sec_score(sev):
    return {"CRITICAL": "9.0", "HIGH": "7.5", "MEDIUM": "5.0", "LOW": "3.0"}.get(sev, "5.0")


# ════════════════════════════════════════════════════════════════════ HTML
def render_html(result):
    e = html.escape
    counts = result.counts
    sev_colour = {"CRITICAL": "#7b1fa2", "HIGH": "#b03a2e",
                  "MEDIUM": "#b0760a", "LOW": "#1d4d78"}

    rows = []
    for f in result.sorted_findings():
        taint = ""
        if f.taint_path:
            steps = "".join(
                f"<li><b>line {s.line}</b> &mdash; {e(s.description)}</li>"
                for s in f.taint_path)
            taint = (f"<div class='taint'><b>Evidence &mdash; untrusted input reaches "
                     f"this call:</b><ol>{steps}</ol></div>")
        fix = ""
        if f.fixable and f.fix:
            fix = f"<div class='fix'>Auto-fix available &mdash; {e(f.fix.describe)}</div>"
        rows.append(f"""
        <div class="finding">
          <div class="head">
            <span class="sev" style="background:{sev_colour.get(f.severity,'#555')}">{e(f.severity)}</span>
            <span class="rid">{e(f.rule_id)}</span>
            <span class="loc">{e(f.file)}:{f.line}</span>
            <span class="lang">{e(f.language)}</span>
            {f"<span class='cwe'>{e(f.cwe)}</span>" if f.cwe else ""}
          </div>
          <div class="msg">{e(f.message)}</div>
          <pre class="snip">{e(f.snippet)}</pre>
          <div class="meta"><b>Confidence:</b> {e(f.confidence)} &mdash; {e(f.confidence_reason)}</div>
          <div class="why"><b>Why it matters:</b> {e(f.explanation)}</div>
          <div class="rem"><b>How to fix:</b> {e(f.remediation)}</div>
          {taint}{fix}
        </div>""")

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>SentinelLint report</title><style>
body{{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#f4f7fa;color:#1a1a1a}}
header{{background:#12324f;color:#fff;padding:22px 30px}}
header h1{{margin:0;font-size:20px;letter-spacing:.3px}}
header p{{margin:6px 0 0;color:#b9d0e2;font-size:13px}}
.wrap{{max-width:1080px;margin:0 auto;padding:22px 30px 60px}}
.cards{{display:flex;gap:12px;margin:18px 0 26px;flex-wrap:wrap}}
.card{{background:#fff;border:1px solid #d5dde4;border-radius:6px;padding:12px 18px;min-width:118px}}
.card .n{{font-size:24px;font-weight:700}}
.card .l{{font-size:11px;color:#666;text-transform:uppercase;letter-spacing:.6px}}
.finding{{background:#fff;border:1px solid #d5dde4;border-left:4px solid #12324f;border-radius:5px;padding:14px 18px;margin-bottom:14px}}
.head{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:7px}}
.sev{{color:#fff;padding:2px 9px;border-radius:3px;font-size:11px;font-weight:700}}
.rid{{font-family:ui-monospace,Menlo,Consolas,monospace;font-weight:700;font-size:13px}}
.loc{{color:#555;font-size:12px;font-family:ui-monospace,monospace}}
.lang,.cwe{{background:#eef2f6;border-radius:3px;padding:2px 7px;font-size:11px;color:#12324f}}
.msg{{font-weight:600;margin-bottom:7px}}
.snip{{background:#12324f;color:#e8eef5;padding:9px 12px;border-radius:4px;font-size:12.5px;overflow-x:auto;margin:8px 0}}
.meta,.why,.rem{{font-size:13px;margin:5px 0;line-height:1.5}}
.taint{{background:#fff8e6;border-left:3px solid #c8860d;padding:9px 13px;margin-top:10px;font-size:13px;border-radius:0 4px 4px 0}}
.taint ol{{margin:6px 0 0 18px;padding:0}} .taint li{{margin:3px 0}}
.fix{{background:#eff7f0;border-left:3px solid #2e7d4f;padding:8px 13px;margin-top:9px;font-size:13px;border-radius:0 4px 4px 0}}
.none{{background:#fff;border:1px solid #d5dde4;border-radius:6px;padding:40px;text-align:center;color:#2e7d4f;font-size:16px}}
.warning{{background:#fff8e6;border:1px solid #e0c27a;border-left:4px solid #b0760a;border-radius:5px;padding:12px 16px;margin:0 0 18px;font-size:13px}}
.warning ul{{margin:8px 0 0 18px;padding:0}}
.note{{background:#eef5ff;border:1px solid #b9cde4;border-left:4px solid #2d5d8a;border-radius:5px;padding:12px 16px;margin:0 0 18px;font-size:13px}}
.note ul{{margin:8px 0 0 18px;padding:0}}
</style></head><body>
<header><h1>SentinelLint &mdash; Static Analysis Report</h1>
<p>{result.files_scanned} file(s) scanned in {result.duration:.2f}s &nbsp;&middot;&nbsp;
{len(result.findings)} finding(s) &nbsp;&middot;&nbsp; source code was never executed</p></header>
<div class="wrap">
{("<div class=\"warning\"><b>Scan warnings</b><ul>" + "".join(f"<li>{e(w)}</li>" for w in result.warnings) + "</ul></div>") if result.warnings else ""}
{("<div class=\"note\"><b>Note</b><ul>" + "".join(f"<li>{e(n)}</li>" for n in getattr(result, "notes", [])) + "</ul></div>") if getattr(result, "notes", []) else ""}
<div class="cards">
  <div class="card"><div class="n" style="color:#7b1fa2">{counts['CRITICAL']}</div><div class="l">Critical</div></div>
  <div class="card"><div class="n" style="color:#b03a2e">{counts['HIGH']}</div><div class="l">High</div></div>
  <div class="card"><div class="n" style="color:#b0760a">{counts['MEDIUM']}</div><div class="l">Medium</div></div>
  <div class="card"><div class="n" style="color:#1d4d78">{counts['LOW']}</div><div class="l">Low</div></div>
  <div class="card"><div class="n">{len(all_rules())}</div><div class="l">Rules loaded</div></div>
</div>
{"".join(rows) if rows else ("<div class=\"none\">No findings were reported, but the scan is incomplete. Review the warnings above.</div>" if result.status == "PARTIAL" else "<div class=\"none\">No issues found. Analysis completed successfully.</div>")}
</div></body></html>"""
