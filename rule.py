"""
Rule definitions and the registry.

Adding a rule is isolated to its rule module: subclass
Rule, fill in the metadata, implement check(), and decorate with @register.
The engine discovers it automatically.
"""

from dataclasses import dataclass
from typing import List, Optional

from .finding import (
    Finding, Edit,
    CONF_HIGH, CONF_MEDIUM, CONF_LOW,
)

# Every registered rule, in registration order.
REGISTRY: List["Rule"] = []


def register(cls):
    """Class decorator that instantiates a rule and adds it to the registry."""
    REGISTRY.append(cls())
    return cls


def rules_for(language: str) -> List["Rule"]:
    return [r for r in REGISTRY if r.language == language and r.enabled]


def all_rules() -> List["Rule"]:
    return list(REGISTRY)


class Rule:
    """Base class for every rule in every language."""

    id: str = ""
    language: str = ""
    category: str = ""          # security | quality | style
    severity: str = "MEDIUM"
    base_confidence: str = CONF_MEDIUM
    cwe: Optional[str] = None
    message: str = ""
    explanation: str = ""
    remediation: str = ""
    fixable: bool = False
    enabled: bool = True

    # ------------------------------------------------------------------
    def make(self, ctx, line, col=0, end_line=None, end_col=None,
             message=None, confidence=None, confidence_reason="",
             taint_path=None, fix=None, severity=None) -> Finding:
        """Build a Finding from this rule's metadata plus a source location."""
        return Finding(
            rule_id=self.id,
            language=self.language,
            category=self.category,
            severity=severity or self.severity,
            confidence=confidence or self.base_confidence,
            confidence_reason=confidence_reason or self.default_confidence_reason(),
            file=ctx.filename,
            line=line,
            col=col,
            end_line=end_line if end_line is not None else line,
            end_col=end_col,
            snippet=ctx.line_text(line),
            message=message or self.message,
            explanation=self.explanation,
            remediation=self.remediation,
            cwe=self.cwe,
            taint_path=taint_path or [],
            fixable=bool(fix) or self.fixable,
            fix=fix,
        )

    def default_confidence_reason(self) -> str:
        if self.base_confidence == CONF_HIGH:
            return "this API is unsafe regardless of its arguments"
        if self.base_confidence == CONF_LOW:
            return "heuristic rule - review before acting"
        return "dangerous API reached, argument not traced to a source"

    # ------------------------------------------------------------------
    def check(self, node, ctx) -> List[Finding]:
        """Inspect one node. Return zero or more findings."""
        raise NotImplementedError


@dataclass
class Context:
    """Everything a rule needs to know about the file being analysed."""

    filename: str
    source: str
    language: str

    def __post_init__(self):
        self.lines = self.source.splitlines()
        self._suppressed = _collect_suppressions(self.source, self.language)
        self.imports = {}       # alias -> real module/function name
        self.taint = {}         # populated per-function by the taint engine
        self.function = None    # enclosing function node, when known
        self.constants = {}     # module-level NAME -> literal value
        self.assignments = {}   # (function-id, name) -> assignments ordered by line

    def line_text(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1].strip()
        return ""

    def is_suppressed(self, line: int, rule_id: str) -> bool:
        entry = self._suppressed.get(line)
        if entry is None:
            return False
        return entry == "*" or rule_id in entry

    def assignment_before(self, name: str, line: int, function=None):
        """Return the latest simple assignment to *name* at or before *line*."""
        key = (id(function) if function is not None else None, name)
        items = self.assignments.get(key, ())
        best = None
        for node in items:
            if node.lineno <= line:
                best = node
            else:
                break
        return best

    def resolve(self, name: str) -> str:
        """Map a local alias back to the real name it was imported as.

        Lets a rule see through  `import subprocess as sp`  and
        `from os import system`, which a plain name check would miss.
        """
        return self.imports.get(name, name)


def _collect_suppressions(source: str, language: str) -> dict:
    """Find  usict: ignore  comments.

    Python's ast module discards comments entirely, so suppression has to be
    recovered from the raw text. We only look at the comment portion of each
    line, so the word never matches inside a string literal.
    """
    marks = {}
    comment_tokens = ("#",) if language == "python" else ("//", "/*")
    for i, raw in enumerate(source.splitlines(), start=1):
        for tok in comment_tokens:
            if tok not in raw:
                continue
            comment = raw.split(tok, 1)[1]
            if "usict:" not in comment or "ignore" not in comment:
                continue
            after = comment.split("ignore", 1)[1].strip().strip(":").strip()
            marks[i] = [p.strip() for p in after.replace(",", " ").split() if p.strip()] or "*"
            break
    return marks
