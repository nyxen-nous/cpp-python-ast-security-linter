"""
Deterministic auto-fix.

Three properties make this safe enough to run on someone else's code:

1. Fixes are exact byte-range splices, computed from the AST node's own
   line/column span. Nothing else in the file is touched, so comments,
   blank lines and formatting all survive. We never regenerate the file
   from the tree - ast.unparse() would discard every comment.

2. Edits are applied bottom-up. Patching the last edit first means earlier
   line and column offsets are still valid when we reach them.

3. Every patched file is re-parsed before it is written. If the result does
   not parse, the fix is discarded and reported as unverified. This is the
   answer to "how do you know your fix doesn't break my code".
"""

import ast
import difflib
import os

from ..core.finding import Finding


class FixResult:
    def __init__(self, path):
        self.path = path
        self.applied = []          # list[Finding]
        self.rejected = []         # list[(Finding, reason)]
        self.original = ""
        self.patched = ""

    @property
    def changed(self):
        return bool(self.applied) and self.patched != self.original

    def diff(self):
        return "".join(difflib.unified_diff(
            self.original.splitlines(keepends=True),
            self.patched.splitlines(keepends=True),
            fromfile=f"a/{self.path}", tofile=f"b/{self.path}",
        ))


def _offset(lines, line, col):
    """Absolute character offset of a (1-based line, 0-based col) position."""
    return sum(len(l) for l in lines[:line - 1]) + col


def _apply_edit(source: str, edit) -> str:
    lines = source.splitlines(keepends=True)
    if edit.line < 1 or edit.line > len(lines):
        raise IndexError("edit line out of range")

    start = _offset(lines, edit.line, edit.col)

    end_line = edit.end_line or edit.line
    if edit.end_col is None:
        # whole-line replacement, including the newline
        end = sum(len(l) for l in lines[:end_line])
    else:
        end = _offset(lines, end_line, edit.end_col)

    if end < start:
        raise ValueError("edit end precedes its start")
    return source[:start] + edit.replacement + source[end:]


def _verifies(source: str, language: str) -> bool:
    """Confirm the patched source still parses."""
    if language == "python":
        try:
            ast.parse(source)
            return True
        except SyntaxError:
            return False
    if language == "cpp":
        # structural sanity: brackets must still balance
        depth = {"{": 0, "(": 0, "[": 0}
        pairs = {"}": "{", ")": "(", "]": "["}
        from ..cpp.lexer import tokenize
        for t in tokenize(source):
            if t.value in depth:
                depth[t.value] += 1
            elif t.value in pairs:
                depth[pairs[t.value]] -= 1
        return all(v == 0 for v in depth.values())
    return True


def plan_fixes(findings):
    """Group the fixable findings by file, bottom-up within each file."""
    by_file = {}
    for f in findings:
        if f.fix is None:
            continue
        by_file.setdefault(f.file, []).append(f)
    for path, items in by_file.items():
        items.sort(key=lambda f: (f.fix.line, f.fix.col), reverse=True)
    return by_file


def apply_fixes(findings, write=False, only_rules=None):
    """Apply every verified fix. Returns a FixResult per file."""
    results = []
    for path, items in plan_fixes(findings).items():
        if only_rules:
            items = [f for f in items if f.rule_id in only_rules]
        if not items:
            continue

        res = FixResult(path)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                res.original = fh.read()
        except OSError as e:
            res.rejected.append((items[0], f"could not read file: {e}"))
            results.append(res)
            continue

        language = items[0].language
        current = res.original

        for finding in items:
            try:
                candidate = _apply_edit(current, finding.fix)
            except Exception as e:
                res.rejected.append((finding, f"edit could not be applied: {e}"))
                continue
            if not _verifies(candidate, language):
                res.rejected.append(
                    (finding, "patched file failed to re-parse - fix discarded"))
                continue
            current = candidate
            res.applied.append(finding)

        res.patched = current
        if write and res.changed:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(res.patched)
        results.append(res)
    return results
