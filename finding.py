"""
The single Finding object that every rule returns, in every language.

Freezing this schema is what lets the Python analyzer and the C++ analyzer
feed one unified report. The reporting layer never needs to know which
language or which rule produced a result.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional


# ---------------------------------------------------------------- severity
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}

# -------------------------------------------------------------- confidence
# Deliberately three named levels, never a decimal. A number like "0.94"
# implies a probability model we do not have; a judge is right to ask where
# it came from. Every finding also carries confidence_reason explaining
# which of these rules was applied.
CONF_HIGH = "HIGH"        # unconditionally dangerous API, or a proven taint path
CONF_MEDIUM = "MEDIUM"    # dangerous API reached with a non-constant argument
CONF_LOW = "LOW"          # pattern present but argument is constant / heuristic rule

CONFIDENCE_ORDER = {CONF_HIGH: 0, CONF_MEDIUM: 1, CONF_LOW: 2}


@dataclass
class TaintStep:
    """One hop on the path from an untrusted source to a dangerous sink."""
    line: int
    kind: str          # "source" | "propagate" | "sink"
    description: str

    def to_dict(self):
        return asdict(self)


@dataclass
class Edit:
    """A single deterministic source edit produced by an auto-fixable rule.

    Positions are 0-based column offsets on 1-based line numbers, matching
    Python's ast module. The fix engine splices exactly this byte range and
    leaves every other character - including comments - untouched.
    """
    line: int
    col: int
    end_line: int
    end_col: int
    replacement: str
    describe: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class Finding:
    rule_id: str
    language: str                     # "python" | "cpp"
    category: str                     # "security" | "quality" | "style"
    severity: str
    confidence: str
    file: str
    line: int
    message: str
    explanation: str = ""
    remediation: str = ""
    cwe: Optional[str] = None
    col: int = 0
    end_line: Optional[int] = None
    end_col: Optional[int] = None
    snippet: str = ""
    confidence_reason: str = ""
    taint_path: List[TaintStep] = field(default_factory=list)
    fixable: bool = False
    fix: Optional[Edit] = None

    # ------------------------------------------------------------------
    def sort_key(self):
        return (self.file, self.line, self.col, self.rule_id)

    def to_dict(self):
        d = asdict(self)
        d["taint_path"] = [s.to_dict() for s in self.taint_path]
        d["fix"] = self.fix.to_dict() if self.fix else None
        return d

    def __repr__(self):
        return f"<{self.severity} {self.rule_id} {self.file}:{self.line}>"
