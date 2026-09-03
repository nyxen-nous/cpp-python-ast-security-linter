"""
Python analysis front end.

Parses a file into an AST, resolves import aliases so that rules can see
through `import subprocess as sp`, runs the taint pass, then offers every
node to every registered Python rule.
"""

import ast

from ..core.finding import Finding, LOW, CONF_HIGH
from ..core.rule import Context, rules_for
from . import rules as _rules          # noqa: F401  (registers the rules)
from .taint import TaintAnalyzer

LANG = "python"


def _collect_imports(tree):
    """Map every local alias to the real dotted name it refers to.

    `import subprocess as sp`      -> {"sp": "subprocess"}
    `from os import system`        -> {"system": "os.system"}
    `from os import system as sh`  -> {"sh": "os.system"}
    """
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[(a.asname or a.name).split(".")[0]] = a.name
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for a in node.names:
                if a.name == "*":
                    continue
                aliases[a.asname or a.name] = f"{mod}.{a.name}" if mod else a.name
    return aliases


def _collect_assign_aliases(tree, aliases):
    """Follow simple rebinding such as  `e = eval`  or  `run = subprocess.run`."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        tgt = node.targets[0]
        if not isinstance(tgt, ast.Name):
            continue
        v = node.value
        if isinstance(v, ast.Name):
            aliases[tgt.id] = aliases.get(v.id, v.id)
        elif isinstance(v, ast.Attribute):
            parts, cur = [], v
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(aliases.get(cur.id, cur.id))
                aliases[tgt.id] = ".".join(reversed(parts))
    return aliases


def _collect_module_constants(tree):
    """Map module-level `NAME = <literal>` bindings to their value.

    Lets a rule tell `open(BASE + name)` - where BASE is a module constant and
    `name` is the variable part - from `open(BASE + "fixed.txt")`, which
    splices nothing dynamic and is not a path-traversal risk.

    Only module scope is collected, and a name assigned more than once is
    dropped: if it is rebound anywhere, treating it as constant is unsound.
    """
    consts, rebound = {}, set()
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not (isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            continue
        for t in node.targets:
            if not isinstance(t, ast.Name):
                continue
            if t.id in consts:
                rebound.add(t.id)
            consts[t.id] = node.value.value
    for name in rebound:
        consts.pop(name, None)
    return consts


def _annotate_functions_and_assignments(tree, ctx):
    """Annotate nodes with their enclosing function and index simple assignments."""
    assignments = {}
    for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        for sub in ast.walk(fn):
            sub._usict_fn = fn  # noqa: SLF001
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            continue
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target] if node.target is not None else []
        else:
            targets = [node.target]
        fn = getattr(node, "_usict_fn", None)
        for target in targets:
            if isinstance(target, ast.Name):
                assignments.setdefault((id(fn) if fn is not None else None, target.id), []).append(node)
    for items in assignments.values():
        items.sort(key=lambda n: n.lineno)
    ctx.assignments = assignments


def analyze_source(source: str, filename: str):
    """Analyse one Python file. Never raises on bad input."""
    ctx = Context(filename=filename, source=source, language=LANG)

    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as e:
        return [Finding(
            rule_id="PARSE.001",
            language=LANG,
            category="quality",
            severity=LOW,
            confidence=CONF_HIGH,
            confidence_reason="the Python parser rejected this file",
            file=filename,
            line=e.lineno or 1,
            col=(e.offset or 1) - 1,
            message=f"File could not be parsed: {e.msg}",
            explanation=("The analyzer reports unparseable files as a low-severity "
                         "finding instead of crashing, so one bad file never stops a "
                         "scan of the rest of the project."),
            remediation="Fix the syntax error, or exclude generated files from the scan.",
        )]
    except (ValueError, RecursionError) as e:
        return [Finding(
            rule_id="PARSE.002", language=LANG, category="quality",
            severity=LOW, confidence=CONF_HIGH,
            confidence_reason="parser raised an unexpected error",
            file=filename, line=1, col=0,
            message=f"File could not be parsed: {e}",
            explanation="The file was rejected by the parser before analysis could start.",
            remediation="Check the file encoding and that it is really Python source.",
        )]

    ctx.imports = _collect_assign_aliases(tree, _collect_imports(tree))
    ctx.constants = _collect_module_constants(tree)
    _annotate_functions_and_assignments(tree, ctx)

    # taint pass first, so rules can consult it
    ta = TaintAnalyzer(ctx)
    ta.analyze_module(tree)
    ctx.taint_analyzer = ta

    active = rules_for(LANG)
    findings = []

    # module-level rules see the Module node once
    for rule in active:
        try:
            findings.extend(rule.check(tree, ctx) or [])
        except Exception as exc:
            findings.append(Finding(
                rule_id="ENGINE.001", language=LANG, category="quality",
                severity=LOW, confidence=CONF_HIGH, file=filename, line=1, col=0,
                message=f"Rule {rule.id} failed during analysis: {type(exc).__name__}",
                explanation=("One analysis rule raised an internal exception. The scan "
                             "continues, but the result is marked incomplete instead of "
                             "silently omitting that rule."),
                remediation="Review the rule error and rerun the scan after correcting it.",
            ))

    # per-node rules, with the enclosing function tracked for context
    for node in ast.walk(tree):
        if isinstance(node, ast.Module):
            continue
        ctx.function = getattr(node, "_usict_fn", None)
        for rule in active:
            try:
                findings.extend(rule.check(node, ctx) or [])
            except Exception as exc:
                findings.append(Finding(
                    rule_id="ENGINE.001", language=LANG, category="quality",
                    severity=LOW, confidence=CONF_HIGH, file=filename,
                    line=getattr(node, "lineno", 1), col=getattr(node, "col_offset", 0),
                    message=f"Rule {rule.id} failed during analysis: {type(exc).__name__}",
                    explanation=("One analysis rule raised an internal exception. The scan "
                                 "continues, but the result is marked incomplete instead of "
                                 "silently omitting that rule."),
                    remediation="Review the rule error and rerun the scan after correcting it.",
                ))

    # de-duplicate and honour suppression comments
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
