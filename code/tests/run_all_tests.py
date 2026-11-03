"""
Comprehensive test runner for all test modules under code/tests/.
Uses sys.executable for isolated execution.
"""
import os
import sys
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TESTS_DIR = os.path.join(ROOT, "code", "tests")

def main():
    test_files = [
        "test_intent_classifier.py",
        "test_metamorphic.py",
        "test_reported_status_invariance.py",
        "test_identity_resolution.py",
        "test_audit_cutoff.py",
        "test_case_isolation.py",
        "test_validator_contract.py",
        "test_output_invariants.py",
        "test_custom_cases.py",
        "test_phase4_stress.py",
        "test_security_robustness.py",
    ]

    print("=================================================================")
    print("RUNNING ALL ENGINE UNIT AND INTEGRITY TESTS")
    print(f"Interpreter: {sys.executable}")
    print("=================================================================")

    results = []
    all_passed = True

    for tf in test_files:
        tpath = os.path.join(TESTS_DIR, tf)
        if not os.path.exists(tpath):
            results.append((tf, "MISSING", 0.0, "File not found"))
            all_passed = False
            continue

        start = __import__("time").time()
        res = subprocess.run([sys.executable, tpath], capture_output=True, text=True)
        dur = __import__("time").time() - start

        if res.returncode == 0:
            results.append((tf, "PASS", dur, res.stdout.strip().split("\n")[-1]))
        else:
            all_passed = False
            err_line = res.stderr.strip().split("\n")[-1] if res.stderr else res.stdout.strip().split("\n")[-1]
            results.append((tf, "FAIL", dur, err_line))

    print("\n| Test Module | Status | Duration | Detail |")
    print("|---|---|---|---|")
    for tf, status, dur, detail in results:
        print(f"| {tf} | **{status}** | {dur:.2f}s | {detail} |")

    print("\nOVERALL TEST SUITE:", "PASS" if all_passed else "FAIL")
    if not all_passed:
        sys.exit(1)

if __name__ == "__main__":
    main()
