"""Targeted hardening tests for the hackathon build.

This supplements the annotated validation corpus with behavioral checks for
project ignores, baselines, partial-scan semantics, and the C++ sizeof fix.
"""

import json
import os
import sys
import subprocess
import tempfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from analyzer.core.baseline import filter_baseline, save_baseline, load_baseline
from analyzer.core.engine import scan
from analyzer.core.rule import all_rules
import analyzer.python  # registers Python rules
import analyzer.cpp     # registers C++ rules

ROOT = Path(__file__).resolve().parent


def main():
    checks = []

    # New SIH security coverage stays explicitly registered and counted.
    rule_ids = {r.id for r in all_rules()}
    expected_new = {
        "PY.SEC.013", "PY.SEC.014", "PY.SEC.015", "PY.SEC.016", "PY.SEC.017",
        "CPP.SEC.010", "CPP.SEC.011", "CPP.SEC.012", "CPP.SEC.013", "CPP.SEC.014",
    }
    checks.append((expected_new <= rule_ids and len(all_rules()) == 42,
                   "42-rule catalog includes the advanced security checks"))

    # C++ sizeof() should be treated as a compile-time bound.
    sizeof_file = ROOT / "edge" / "cpp_sizeof_safe.cpp"
    checks.append((len(scan(str(sizeof_file)).findings) == 0, "sizeof safe case"))

    adv_py = scan(str(ROOT / "vulnerable" / "advanced_python.py"))
    adv_py_ids = {f.rule_id for f in adv_py.findings}
    checks.append((expected_new & {"PY.SEC.013", "PY.SEC.014", "PY.SEC.015", "PY.SEC.016", "PY.SEC.017"} <= adv_py_ids,
                   "advanced Python security rules fire"))
    adv_cpp = scan(str(ROOT / "vulnerable" / "advanced_cpp.cpp"))
    adv_cpp_ids = {f.rule_id for f in adv_cpp.findings}
    checks.append((expected_new & {"CPP.SEC.010", "CPP.SEC.011", "CPP.SEC.012", "CPP.SEC.013", "CPP.SEC.014"} <= adv_cpp_ids,
                   "advanced C++ security rules fire"))

    # Weak randomness is only meaningful when used for a security-sensitive name.
    with tempfile.TemporaryDirectory() as td:
        ordinary = Path(td) / "ordinary.cpp"
        ordinary.write_text("int roll(){ return rand(); }\n")
        sensitive = Path(td) / "sensitive.cpp"
        sensitive.write_text("int auth_token(){ return rand(); }\n")
        checks.append((not any(f.rule_id == "CPP.SEC.005" for f in scan(str(ordinary)).findings),
                       "rand() in ordinary code stays silent"))
        checks.append((any(f.rule_id == "CPP.SEC.005" for f in scan(str(sensitive)).findings),
                       "rand() in security context is reported"))

    safe_adv = scan(str(ROOT / "safe" / "advanced_python.py"))
    safe_adv_cpp = scan(str(ROOT / "safe" / "advanced_cpp.cpp"))
    checks.append((not safe_adv.findings and not safe_adv_cpp.findings,
                   "advanced safe counterparts stay clean"))

    # Project ignore should exclude the ignored directory, while the visible
    # file remains analyzable.
    proj = ROOT / "edge" / "project_ignore"
    result = scan(str(proj))
    visible = [f for f in result.findings if "hidden.py" in f.file]
    checks.append((not visible, ".sentinellintignore excludes hidden.py"))
    checks.append((any("visible.py" in f.file for f in result.findings), "visible.py still scanned"))

    # Baseline round-trip suppresses the same findings and records a note.
    vuln = ROOT / "vulnerable"
    baseline_target = scan(str(vuln))
    with tempfile.TemporaryDirectory() as td:
        bp = os.path.join(td, "baseline.json")
        save_baseline(bp, baseline_target.findings, root=str(vuln))
        keys = load_baseline(bp)
        filtered, suppressed = filter_baseline(baseline_target.findings, keys, root=str(vuln))
        checks.append((not filtered and suppressed == len(baseline_target.findings), "baseline suppresses known findings"))
        data = json.loads(Path(bp).read_text())
        checks.append((data.get("formatVersion") == 1, "baseline format is versioned"))

        # Finding identity should survive unrelated line movement.
        shifted = baseline_target.findings[0]
        shifted.line += 10
        shifted.snippet = shifted.snippet
        filtered2, suppressed2 = filter_baseline([shifted], keys, root=str(vuln))
        checks.append((not filtered2 and suppressed2 == 1,
                       "baseline identity survives line shifts"))

    # Tar extraction: explicit safe filter is clean; explicit unsafe filter is not.
    tar_src = "import tarfile\nwith tarfile.open('x.tar') as tar:\n    tar.extractall('/tmp/app')\n"
    tar_unsafe = "import tarfile\nwith tarfile.open('x.tar') as tar:\n    tar.extractall('/tmp/app', filter=None)\n"
    from analyzer.python.analyzer import analyze_source
    tar_f = analyze_source(tar_src, "tar_demo.py")
    tar_u = analyze_source(tar_unsafe, "tar_unsafe.py")
    checks.append((any(f.rule_id == "PY.SEC.017" for f in tar_f),
                   "tar extraction without explicit filter is reported as version-dependent"))
    checks.append((any(f.rule_id == "PY.SEC.017" and f.severity == "CRITICAL" for f in tar_u) or
                   any(f.rule_id == "PY.SEC.017" and f.confidence == "HIGH" for f in tar_u),
                   "explicit unsafe tar filter is reported strongly"))

    # Missing paths are a hard error status rather than an empty clean scan.
    missing = scan(str(ROOT / "does-not-exist"))
    checks.append((missing.status == "ERROR", "missing path status is ERROR"))

    # --- secret-name qualifier suppression (PY.SEC.003 / CPP.SEC.009) -------
    # Regression guard for the stdlib false positives: a credential word used
    # as a qualifier must not be reported.
    quals = scan(str(ROOT / "edge" / "secret_qualifiers.py"))
    secret_fps = [f for f in quals.findings if f.rule_id == "PY.SEC.003"]
    checks.append((not secret_fps,
                   f"secret qualifiers produce no findings ({len(secret_fps)} found)"))

    # The suppression must not swallow the real detections.
    reals = scan(str(ROOT / "edge" / "secret_true_positives.py"))
    real_hits = {f.line for f in reals.findings if f.rule_id == "PY.SEC.003"}
    checks.append((len(real_hits) == 7,
                   f"all 7 real secrets still detected ({len(real_hits)} found)"))

    cpp_edge = scan(str(ROOT / "edge" / "cpp_secret_edge.cpp"))
    cpp_secrets = [f for f in cpp_edge.findings if f.rule_id == "CPP.SEC.009"]
    checks.append((len(cpp_secrets) == 2,
                   f"C++ reports pw and password only ({len(cpp_secrets)} found)"))

    # --- path construction fallback (PY.SEC.012) ---------------------------
    paths = scan(str(ROOT / "edge" / "path_build.py"))
    path_lines = sorted(f.line for f in paths.findings if f.rule_id == "PY.SEC.012")
    checks.append((len(path_lines) == 4,
                   f"4 constructed paths reported ({len(path_lines)} found)"))
    # os.path.join and constant paths live below the last reported case.
    joined = scan(str(ROOT / "edge" / "path_build.py"))
    safe_half = [f for f in joined.findings
                 if f.rule_id == "PY.SEC.012" and f.line > 36]
    checks.append((not safe_half,
                   "os.path.join and constant paths are not reported"))

    # --- scan caps are large enough for a real repository ------------------
    from analyzer.core.engine import MAX_FILES, MAX_SECONDS
    checks.append((MAX_FILES >= 5000 and MAX_SECONDS >= 120,
                   f"scan caps sized for real repos ({MAX_FILES} files/{MAX_SECONDS}s)"))

    # Constant string construction should not be classified as dynamic SQL.
    sql_constant = scan(str(ROOT / "edge" / "sql_constant_flow.py"))
    checks.append((not any(f.rule_id == "PY.SEC.008" for f in sql_constant.findings),
                   "constant SQL construction is not reported"))

    # SQL constructed in a variable should still be detected at the sink.
    sql_flow = scan(str(ROOT / "edge" / "sql_variable_flow.py"))
    checks.append((any(f.rule_id == "PY.SEC.008" for f in sql_flow.findings),
                   "SQL injection detected through a query variable"))

    # verify=False should be detected even when the value is first assigned.
    verify_flow = scan(str(ROOT / "edge" / "requests_verify_variable.py"))
    checks.append((any(f.rule_id == "PY.SEC.009" for f in verify_flow.findings),
                   "verify=False detected through a variable"))

    # Limited same-file cross-function taint should carry evidence into the sink.
    cross = scan(str(ROOT / "edge" / "cross_function_taint.py"))
    cross_hits = [f for f in cross.findings if f.rule_id == "PY.SEC.008" and f.taint_path]
    checks.append((bool(cross_hits) and any(s.kind == "call" for s in cross_hits[0].taint_path),
                   "cross-function taint carries a call edge"))

    # Smart-pointer ownership should not look like a leaked raw allocation.
    raii = scan(str(ROOT / "edge" / "cpp_raii_safe.cpp"))
    checks.append((not any(f.rule_id == "CPP.SEC.008" for f in raii.findings),
                   "smart-pointer ownership not flagged as a leak"))

    # HTML escaping is not a sanitizer for code execution, while shell quoting
    # is useful for shell sinks.
    sanitizer = scan(str(ROOT / "edge" / "taint_sanitizer_context.py"))
    ids = [f.rule_id for f in sanitizer.findings]
    checks.append(("PY.SEC.002" not in ids and "PY.SEC.001" in ids,
                   "sanitizer is evaluated in sink context"))

    # Rule failures must be visible rather than silently swallowed.
    registry = all_rules()
    target_rule = registry[0]
    original_check = target_rule.check
    def _boom(node, ctx):
        raise RuntimeError("intentional regression test")
    target_rule.check = _boom
    try:
        broken = scan(str(ROOT / "safe" / "example_safe.py"))
        checks.append((broken.status == "PARTIAL" and any(f.rule_id == "ENGINE.001" for f in broken.findings),
                       "rule failures are reported and mark scan partial"))
    finally:
        target_rule.check = original_check

    # PARTIAL/ERROR scans must not silently pass CI.
    malformed = ROOT / "malformed" / "truncated.cpp"
    proc = subprocess.run([sys.executable, str(ROOT.parent / "run.py"), str(malformed), "--fail-on", "HIGH"],
                          capture_output=True, text=True)
    checks.append((proc.returncode == 2, "partial scan returns CI error code 2"))

    # A sanitizer wrapping a source directly must suppress the taint path,
    # matching the two-step form. Guards a HIGH-confidence false positive on
    # the common `int(request.args.get(...))` shape.
    wrapped = scan(str(ROOT / "edge" / "sanitizer_wrapped_source.py"))
    traced = [f for f in wrapped.findings if f.taint_path]
    checks.append((len(traced) == 1,
                   f"sanitizer-wrapped source yields one traced path ({len(traced)})"))

    failed = [name for ok, name in checks if not ok]
    for ok, name in checks:
        print(f"[{ 'PASS' if ok else 'FAIL' }] {name}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
