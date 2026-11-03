"""
Invariant tests over all 518 outputs in output.csv.
Enforces:
- exactly 518 rows sorted by case_id
- valid JSON array
- allowed operation/state/phase combos
- phase order: FINDING < REMEDIATION < VERIFICATION
- consecutive step_no from 1
- evidence_id exists in manifest and captured_at <= audit_at
- future steps (remediation and post-remediation verification in INCOMPLETE) have empty evidence_id
- COMPLETE has only VERIFICATION steps and non-empty evidence_id
- NOT_APPLICABLE has steps_json = []
- no duplicate (operation, system_id, resource_id) within steps
- reports predicted status distribution vs gold distribution
"""
import os
import sys
import csv
import json
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUTPUT_CSV = os.path.join(ROOT, "output.csv")
REQUESTS_CSV = os.path.join(ROOT, "dataset", "deletion_requests.csv")
EVIDENCE_CSV = os.path.join(ROOT, "dataset", "evidence_files.csv")
SAMPLES_GOLD_CSV = os.path.join(ROOT, "dataset", "sample_output.csv")

ALLOWED_OPS = {
    "FINDING": {
        "REPORT_REMAINING_RECORD": "PRESENT",
        "REPORT_EXPOSED_PII": "PRESENT",
        "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
        "REPORT_RESTORE_RISK": "ACTIVE",
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW": "DISABLED",
        "BLOCK_RESTORE": "BLOCKED",
        "DELETE_RECORD": "ABSENT",
        "REDACT_RECORD": "REDACTED",
        "ANONYMIZE_RECORD": "ANONYMIZED",
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT": "ABSENT",
        "VERIFY_RECORD_PRESENT": "PRESENT",
        "VERIFY_RECORD_REDACTED": "REDACTED",
        "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
        "VERIFY_RESTORE_BLOCKED": "BLOCKED",
    }
}

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}

def test_invariants():
    assert os.path.exists(OUTPUT_CSV), f"Missing {OUTPUT_CSV}"
    assert os.path.exists(REQUESTS_CSV), f"Missing {REQUESTS_CSV}"

    with open(REQUESTS_CSV, "r", encoding="utf-8") as f:
        req_rows = list(csv.DictReader(f))
    req_map = {r["case_id"]: r for r in req_rows}
    assert len(req_rows) == 518, f"Expected 518 requests, got {len(req_rows)}"

    manifest = {}
    if os.path.exists(EVIDENCE_CSV):
        with open(EVIDENCE_CSV, "r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                manifest[r["file_id"]] = r.get("captured_at", "")

    with open(OUTPUT_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == ["case_id", "deletion_status", "steps_json"], f"Invalid header: {reader.fieldnames}"
        rows = list(reader)

    assert len(rows) == 518, f"Expected exactly 518 output rows, got {len(rows)}"

    # Sorted by case_id
    expected_ids = sorted(req_map.keys())
    actual_ids = [r["case_id"] for r in rows]
    assert actual_ids == expected_ids, "Rows are not sorted ascending by case_id"

    status_counts = Counter()

    for r in rows:
        cid = r["case_id"]
        status = r["deletion_status"]
        assert status in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"), f"{cid}: invalid status {status}"
        status_counts[status] += 1

        steps = json.loads(r["steps_json"])
        assert isinstance(steps, list), f"{cid}: steps_json is not an array"

        if status == "NOT_APPLICABLE":
            assert steps == [], f"{cid}: NOT_APPLICABLE must have empty steps_json [], got {steps}"
            continue

        if status == "COMPLETE":
            assert len(steps) > 0, f"{cid}: COMPLETE case must have evidence-backed verification steps"

        req = req_map[cid]
        audit_at = req.get("audit_at", "")

        last_phase_val = -1
        seen_ops = set()

        for idx, s in enumerate(steps, 1):
            assert s.get("step_no") == idx, f"{cid}: step_no must be consecutive starting from 1 (step {idx} got {s.get('step_no')})"

            phase = s.get("phase")
            assert phase in PHASE_ORDER, f"{cid}: invalid phase {phase}"
            assert PHASE_ORDER[phase] >= last_phase_val, f"{cid}: phase {phase} appeared after later phase"
            last_phase_val = PHASE_ORDER[phase]

            op = s.get("operation")
            st = s.get("state")
            sys_id = s.get("system_id")
            res_id = s.get("resource_id")
            eid = s.get("evidence_id", "")

            # No duplicate (op, sys_id, res_id)
            step_tuple = (op, sys_id, res_id)
            assert step_tuple not in seen_ops, f"{cid}: duplicate step tuple {step_tuple}"
            seen_ops.add(step_tuple)

            # Allowed operation / state
            assert op in ALLOWED_OPS[phase], f"{cid}: operation {op} not allowed in phase {phase}"
            assert ALLOWED_OPS[phase][op] == st, f"{cid}: state {st} not allowed for {op} in {phase} (expected {ALLOWED_OPS[phase][op]})"

            if status == "COMPLETE":
                assert phase == "VERIFICATION", f"{cid}: COMPLETE case may only have VERIFICATION steps, got {phase}"
                assert eid != "", f"{cid}: COMPLETE verification step must cite non-empty evidence_id"
            elif status == "INCOMPLETE":
                if phase == "FINDING":
                    assert eid != "", f"{cid}: FINDING step must cite non-empty evidence_id"
                else:
                    assert eid == "", f"{cid}: future {phase} step must have empty evidence_id, got '{eid}'"

            if eid:
                assert eid in manifest, f"{cid}: cited evidence_id '{eid}' does not exist in manifest"
                cap = manifest[eid]
                if cap and audit_at:
                    assert cap <= audit_at, f"{cid}: cited evidence '{eid}' (captured {cap}) was captured after audit_at {audit_at}"

    print(f"All 518 rows pass invariant checks! Status distribution: {dict(status_counts)}")

if __name__ == "__main__":
    test_invariants()
    print("test_output_invariants: PASS")
