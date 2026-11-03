"""
IntegrityChecks — Automated validation gating pipeline atomic replace.
Enforces all challenge contract and consistency requirements.
"""
import os
import sys
import csv
import json
import re
import hashlib
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def check_output_contract(output_csv_path, requests_csv_path, evidence_files_csv_path):
    if not os.path.exists(output_csv_path):
        return False, f"Output file missing: {output_csv_path}"

    with open(output_csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != ["case_id", "deletion_status", "steps_json"]:
            return False, f"Invalid header: {reader.fieldnames}"
        rows = list(reader)

    # Load requests to verify case_id ordering and audit_at
    req_rows = list(csv.DictReader(open(requests_csv_path, "r", encoding="utf-8")))
    if len(rows) != len(req_rows):
        return False, f"Row count mismatch: expected {len(req_rows)}, got {len(rows)}"

    req_map = {r["case_id"]: r for r in req_rows}

    # Load evidence manifest
    manifest = {}
    if os.path.exists(evidence_files_csv_path):
        for r in csv.DictReader(open(evidence_files_csv_path, "r", encoding="utf-8")):
            manifest[r["file_id"]] = r.get("captured_at", "")

    # Check case_id ordering
    expected_case_ids = sorted(req_map.keys())
    actual_case_ids = [r["case_id"] for r in rows]
    if actual_case_ids != expected_case_ids:
        return False, "Rows are not sorted ascending by case_id"

    # Per-row checks
    for r in rows:
        cid = r["case_id"]
        status = r["deletion_status"]
        if status not in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
            return False, f"{cid}: invalid deletion_status '{status}'"

        try:
            steps = json.loads(r["steps_json"])
        except Exception as e:
            return False, f"{cid}: invalid JSON in steps_json: {e}"

        if not isinstance(steps, list):
            return False, f"{cid}: steps_json is not an array"

        if status == "NOT_APPLICABLE":
            if steps != []:
                return False, f"{cid}: NOT_APPLICABLE must have empty steps_json [], got {steps}"
            continue

        if status == "COMPLETE":
            if len(steps) == 0:
                return False, f"{cid}: COMPLETE case must have evidence-backed verification steps"

        req = req_map[cid]
        audit_at = req.get("audit_at", "")

        step_no = 1
        last_phase_val = -1
        phase_map = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}

        for s in steps:
            if s.get("step_no") != step_no:
                return False, f"{cid}: step_no must be consecutive starting from 1, expected {step_no} got {s.get('step_no')}"
            step_no += 1

            phase = s.get("phase")
            if phase not in phase_map:
                return False, f"{cid}: invalid phase '{phase}'"

            # Check phase ordering
            if phase_map[phase] < last_phase_val:
                return False, f"{cid}: invalid phase ordering: {phase} followed earlier phase"
            last_phase_val = phase_map[phase]

            op = s.get("operation")
            st = s.get("state")
            eid = s.get("evidence_id", "")

            # Check allowed operation / state pairs
            allowed = {
                "REPORT_REMAINING_RECORD": "PRESENT",
                "REPORT_EXPOSED_PII": "PRESENT",
                "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
                "REPORT_RESTORE_RISK": "ACTIVE",
                "DISABLE_DATA_FLOW": "DISABLED",
                "BLOCK_RESTORE": "BLOCKED",
                "DELETE_RECORD": "ABSENT",
                "REDACT_RECORD": "REDACTED",
                "ANONYMIZE_RECORD": "ANONYMIZED",
                "VERIFY_RECORD_ABSENT": "ABSENT",
                "VERIFY_RECORD_PRESENT": "PRESENT",
                "VERIFY_RECORD_REDACTED": "REDACTED",
                "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
                "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
                "VERIFY_RESTORE_BLOCKED": "BLOCKED",
            }
            if op not in allowed or allowed[op] != st:
                return False, f"{cid}: invalid operation/state pair: {op}/{st}"

            # Evidence rules
            if status == "COMPLETE":
                if phase != "VERIFICATION":
                    return False, f"{cid}: COMPLETE case may only have VERIFICATION steps, got {phase}"
                if not eid:
                    return False, f"{cid}: COMPLETE verification step must cite evidence_id, got empty"
            elif status == "INCOMPLETE":
                if phase == "FINDING":
                    if not eid:
                        return False, f"{cid}: FINDING step must cite evidence_id"
                elif phase in ("REMEDIATION", "VERIFICATION"):
                    if eid != "":
                        return False, f"{cid}: future {phase} step must have empty evidence_id, got '{eid}'"

            # If evidence_id cited, must exist in manifest and captured_at <= audit_at
            if eid and manifest:
                if eid not in manifest:
                    return False, f"{cid}: cited evidence_id '{eid}' does not exist in manifest"
                cap = manifest[eid]
                if cap and audit_at and cap > audit_at:
                    return False, f"{cid}: cited evidence '{eid}' (captured {cap}) was captured after audit_at {audit_at}"

    return True, "Output contract and citations pass"

def check_static_code_integrity(engine_dir):
    forbidden_terms = ["generator.", "generator/", "from generator", "import generator", "dataset/generator"]
    for fname in os.listdir(engine_dir):
        if fname.endswith(".py") and fname != "integrity_checks.py":
            fpath = os.path.join(engine_dir, fname)
            content = open(fpath, "r", encoding="utf-8", errors="ignore").read()
            for term in forbidden_terms:
                if term in content:
                    return False, f"Static check failed: {fname} contains forbidden reference '{term}'"
            # check for hardcoded case_ids
            m = re.search(r'\bcase_\d{3,4}\b', content)
            if m:
                return False, f"Static check failed: {fname} contains hardcoded case_id '{m.group(0)}'"
    return True, "Static code integrity passes"

def run_all_integrity_checks(output_csv_path=None, dataset_dir=None, engine_dir=None):
    root = ROOT
    output_path = output_csv_path or os.path.join(root, "output.csv")
    ds_dir = dataset_dir or os.path.join(root, "dataset")
    eng_dir = engine_dir or os.path.join(root, "code", "engine")

    req_path = os.path.join(ds_dir, "deletion_requests.csv")
    ev_path = os.path.join(ds_dir, "evidence_files.csv")

    ok, msg = check_output_contract(output_path, req_path, ev_path)
    if not ok:
        return False, msg

    ok, msg = check_static_code_integrity(eng_dir)
    if not ok:
        return False, msg

    return True, "All integrity checks passed"

if __name__ == "__main__":
    passed, message = run_all_integrity_checks()
    print("Integrity Check Result:", "PASS" if passed else "FAIL")
    print("Message:", message)
    if not passed:
        sys.exit(1)
