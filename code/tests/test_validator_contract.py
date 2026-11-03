"""
Unit tests for OutputValidator rules and failure conditions.
"""
import os, sys, csv, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "code"))

from engine.output_validator import OutputValidator

def test_validator_detects_malformed_outputs():
    dataset_dir = os.path.join(ROOT, "dataset")

    # Helper to validate a synthetic row list
    def validate_rows(rows):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", encoding="utf-8", newline="") as tf:
            writer = csv.DictWriter(tf, fieldnames=["case_id", "deletion_status", "steps_json"])
            writer.writeheader()
            for r in rows:
                writer.writerow(r)
            tname = tf.name
        try:
            v = OutputValidator(dataset_dir, tname)
            return v.validate()
        finally:
            if os.path.exists(tname):
                os.remove(tname)

    # 1. Invalid status
    bad_status = [{"case_id": "case_001", "deletion_status": "PARTIAL", "steps_json": "[]"}]
    assert validate_rows(bad_status) is False, "Validator accepted invalid deletion_status 'PARTIAL'"

    # 2. NOT_APPLICABLE with non-empty steps
    bad_na = [{"case_id": "case_001", "deletion_status": "NOT_APPLICABLE", "steps_json": '[{"step_no": 1}]'}]
    assert validate_rows(bad_na) is False, "Validator accepted NOT_APPLICABLE with non-empty steps"

    # 3. Non-consecutive step numbers
    bad_step_no = [{
        "case_id": "case_001", "deletion_status": "COMPLETE",
        "steps_json": '[{"step_no": 2, "phase": "VERIFICATION", "system_id": "account_service", "resource_id": "account_001", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "evidence_01"}]'
    }]
    assert validate_rows(bad_step_no) is False, "Validator accepted non-consecutive step_no starting at 2"

if __name__ == "__main__":
    test_validator_detects_malformed_outputs()
    print("test_validator_contract: PASS")
