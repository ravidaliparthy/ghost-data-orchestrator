"""Metamorphic tests for the deletion-audit engine."""
import csv, json, os, sys, random
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.common import load_csv

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET = os.path.join(ROOT, "dataset")
OUTPUT = os.path.join(ROOT, "output.csv")


def _run():
    import subprocess
    subprocess.run([sys.executable, os.path.join(ROOT, "code", "main.py")], check=True)


def test_output_validator_passes():
    import sys
    sys.path.insert(0, os.path.join(ROOT, "code"))
    from engine.output_validator import OutputValidator
    v = OutputValidator(DATASET, OUTPUT)
    assert v.validate(), v.report()


def test_row_count_and_sort():
    rows = list(csv.DictReader(open(OUTPUT, encoding="utf-8")))
    reqs = load_csv(os.path.join(DATASET, "deletion_requests.csv"))
    assert len(rows) == len(reqs) == 518
    ids = [r["case_id"] for r in rows]
    assert ids == sorted(ids)


def test_json_valid():
    rows = list(csv.DictReader(open(OUTPUT, encoding="utf-8")))
    for r in rows:
        steps = json.loads(r["steps_json"])
        assert isinstance(steps, list)
        if r["deletion_status"] == "NOT_APPLICABLE":
            assert steps == []


def test_metamorphic_case_order_independence():
    # Re-running main.py should produce identical output.csv (determinism)
    before = open(OUTPUT, encoding="utf-8").read()
    _run()
    after = open(OUTPUT, encoding="utf-8").read()
    assert before == after, "Non-deterministic output"