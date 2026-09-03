"""
Validation harness.

Reads the EXPECT annotations out of the vulnerable corpus, scans everything,
and reports real precision and recall. Run it with:

    python run.py --selftest

The point of the safe corpus is that it contains the *near-miss* version of
every pattern the analyzer detects - MD5 marked usedforsecurity=False,
a variable literally called password_prompt that holds prompt text, a
parameterised SQL query, eval on a constant. Anything reported there is a
false positive by construction, which is what makes the number meaningful.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import analyzer.cpp        # noqa: E402,F401
import analyzer.python     # noqa: E402,F401
from analyzer.core.engine import scan                 # noqa: E402
from analyzer.core.rule import all_rules              # noqa: E402

EXPECT = re.compile(r"EXPECT\s+([A-Z]+\.[A-Z]+\.\d+)")

VULN_DIR = os.path.join(HERE, "vulnerable")
SAFE_DIR = os.path.join(HERE, "safe")
BAD_DIR = os.path.join(HERE, "malformed")
EDGE_DIR = os.path.join(HERE, "edge")


def expected_rules(path):
    """Every rule ID named in an EXPECT comment in one file."""
    out = set()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = EXPECT.search(line)
            if m:
                out.add(m.group(1))
    return out


def _hr(title):
    print()
    print("=" * 74)
    print(f"  {title}")
    print("=" * 74)


def run_validation():
    ok = True

    _hr("SentinelLint - validation corpus")
    print(f"  {len(all_rules())} rules loaded "
          f"({sum(1 for r in all_rules() if r.language == 'python')} Python, "
          f"{sum(1 for r in all_rules() if r.language == 'cpp')} C++)")

    # ---------------------------------------------------- recall (vulnerable)
    print("\n  RECALL - every EXPECT annotation must be detected\n")
    total_expected = total_found = 0
    for name in sorted(os.listdir(VULN_DIR)):
        path = os.path.join(VULN_DIR, name)
        if not os.path.isfile(path):
            continue
        want = expected_rules(path)
        if not want:
            continue
        got = {f.rule_id for f in scan(path).findings}
        missing = want - got
        total_expected += len(want)
        total_found += len(want & got)
        status = "PASS" if not missing else "FAIL"
        if missing:
            ok = False
        print(f"    [{status}]  {name:<26} {len(want & got)}/{len(want)} expected rules fired")
        for m in sorted(missing):
            print(f"             MISSING: {m}")

    # ------------------------------------------------- precision (safe corpus)
    print("\n  PRECISION - the safe corpus must produce zero findings\n")
    false_positives = []
    for name in sorted(os.listdir(SAFE_DIR)):
        path = os.path.join(SAFE_DIR, name)
        if not os.path.isfile(path):
            continue
        found = scan(path).findings
        false_positives.extend(found)
        status = "PASS" if not found else "FAIL"
        if found:
            ok = False
        print(f"    [{status}]  {name:<26} {len(found)} false positive(s)")
        for f in found:
            print(f"             {f.rule_id} line {f.line}: {f.message}")

    # ------------------------------------------------------- robustness
    print("\n  ROBUSTNESS - hostile input must not crash the analyzer\n")
    crashes = 0
    for name in sorted(os.listdir(BAD_DIR)):
        path = os.path.join(BAD_DIR, name)
        if not os.path.isfile(path):
            continue
        try:
            res = scan(path)
            print(f"    [PASS]  {name:<26} handled, {len(res.findings)} finding(s)")
        except Exception as e:                       # pragma: no cover
            crashes += 1
            ok = False
            print(f"    [FAIL]  {name:<26} CRASHED: {e}")

    # --------------------------------------------------------- edge / regressions
    print("\n  EDGE CASES - safe variants and parser boundaries\n")
    edge_failures = []
    if os.path.isdir(EDGE_DIR):
        for name in sorted(os.listdir(EDGE_DIR)):
            path = os.path.join(EDGE_DIR, name)
            if not os.path.isfile(path):
                continue
            try:
                found = scan(path).findings
            except Exception as e:  # pragma: no cover
                edge_failures.append(f"{name}: crashed with {e}")
                continue
            # An edge file with no EXPECT annotation is a near-miss case and
            # must stay silent. One that carries EXPECT annotations is a
            # regression guard for a detection that was previously missed, so
            # the rules it names must fire and nothing else may.
            want = expected_rules(path)
            if not want:
                if found:
                    edge_failures.extend(f"{name}: {f.rule_id} line {f.line}"
                                         for f in found)
                else:
                    print(f"    [PASS]  {name:<26} safe/edge case produced 0 findings")
                continue
            got = {f.rule_id for f in found}
            missing, extra = want - got, got - want
            if missing or extra:
                for r in sorted(missing):
                    edge_failures.append(f"{name}: expected {r}, not reported")
                for r in sorted(extra):
                    edge_failures.append(f"{name}: unexpected {r}")
            else:
                print(f"    [PASS]  {name:<26} {len(want)} expected rule(s) fired")
        if edge_failures:
            ok = False
            for item in edge_failures:
                print(f"    [FAIL]  {item}")

    # ------------------------------------------------------ taint evidence
    print("\n  TAINT ANALYSIS - source-to-sink paths\n")
    demo = os.path.join(VULN_DIR, "taint_demo.py")
    traced = [f for f in scan(demo).findings if f.taint_path]
    print(f"    {len(traced)} finding(s) carry a full evidence path")
    for f in traced:
        hops = " -> ".join(str(s.line) for s in f.taint_path)
        print(f"      {f.rule_id} line {f.line}  [{f.confidence}]  path: {hops}")
    if not traced:
        ok = False

    # ------------------------------------------------------------ summary
    tp = total_found
    fp = len(false_positives)
    fn = total_expected - total_found
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0

    _hr("RESULTS")
    print(f"    True positives      {tp}")
    print(f"    False positives     {fp}")
    print(f"    False negatives     {fn}")
    print(f"    Precision           {precision * 100:.1f}%")
    print(f"    Recall              {recall * 100:.1f}%")
    print(f"    Crashes             {crashes}")
    print()
    print(f"    {'ALL CHECKS PASSED' if ok else 'SOME CHECKS FAILED'}")
    print()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run_validation())
