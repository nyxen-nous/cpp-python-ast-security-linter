"""
C++ analysis front end.

Mirrors the Python analyzer exactly: parse, walk, offer every node to every
registered C++ rule, then return the same Finding objects. Nothing above
this layer needs to know which language a finding came from.
"""

from ..core.finding import Finding, LOW, CONF_HIGH
from ..core.rule import Context, rules_for
from . import rules as _rules          # noqa: F401  (registers the rules)
from .parser import parse

LANG = "cpp"


def analyze_source(source: str, filename: str):
    ctx = Context(filename=filename, source=source, language=LANG)

    try:
        root = parse(source, filename)
    except Exception as e:
        return [Finding(
            rule_id="PARSE.001", language=LANG, category="quality",
            severity=LOW, confidence=CONF_HIGH,
            confidence_reason="the C++ parser could not build a tree",
            file=filename, line=1, col=0,
            message=f"File could not be parsed: {e}",
            explanation=("The file could not be structurally parsed, so a clean-looking "
                         "result would be unsafe to report."),
            remediation="Check that the file is C/C++ source and is not truncated.",
        )]

    diagnostics = root.extra.get("diagnostics") or []
    parse_findings = [Finding(
        rule_id="PARSE.002", language=LANG, category="quality",
        severity=LOW, confidence=CONF_HIGH,
        confidence_reason="structural delimiter validation found incomplete C++ syntax",
        file=filename, line=line, col=col,
        message=f"Analysis incomplete: {msg}",
        explanation=("The linter detected incomplete or mismatched C++ delimiters. "
                     "Results may be partial and must not be treated as a clean scan."),
        remediation="Complete or correct the C++ source before relying on the scan results.",
    ) for line, col, msg in diagnostics[:10]]

    active = rules_for(LANG)
    findings = parse_findings[:]
    for node in root.walk():
        for rule in active:
            try:
                findings.extend(rule.check(node, ctx) or [])
            except Exception as exc:
                findings.append(Finding(
                    rule_id="ENGINE.001", language=LANG, category="quality",
                    severity=LOW, confidence=CONF_HIGH, file=filename,
                    line=getattr(node, "line", 1), col=getattr(node, "col", 0),
                    message=f"Rule {rule.id} failed during analysis: {type(exc).__name__}",
                    explanation=("One analysis rule raised an internal exception. The scan "
                                 "continues, but the result is marked incomplete instead of "
                                 "silently omitting that rule."),
                    remediation="Review the rule error and rerun the scan after correcting it.",
                ))

    seen, out = set(), []
    for f in findings:
        key = (f.rule_id, f.file, f.line, f.col, f.message)
        if key in seen:
            continue
        seen.add(key)
        if ctx.is_suppressed(f.line, f.rule_id):
            continue
        out.append(f)
    return out


def analyze_file(path: str):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except OSError as e:
        return [Finding(
            rule_id="IO.001", language=LANG, category="quality",
            severity=LOW, confidence=CONF_HIGH, file=path, line=1,
            message=f"Could not read file: {e}",
            explanation="The scan continues with the remaining files.",
            remediation="Check the path and file permissions.",
        )]
    return analyze_source(source, path)
