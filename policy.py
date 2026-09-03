"""Small, dependency-free scan policy helpers.

The policy layer intentionally stays tiny: it gives the CLI/API a stable way
to define which severity should fail CI without coupling the analyzer to any
web framework or database.
"""

from .finding import SEVERITY_ORDER


def normalize_threshold(value):
    if value is None:
        return None
    value = str(value).upper()
    if value not in SEVERITY_ORDER:
        raise ValueError(f"unknown severity threshold: {value}")
    return value


def meets_threshold(finding, threshold):
    threshold = normalize_threshold(threshold)
    if threshold is None:
        return False
    return SEVERITY_ORDER.get(finding.severity, 99) <= SEVERITY_ORDER[threshold]
