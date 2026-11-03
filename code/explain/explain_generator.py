"""
Explainability generator for HackerRank Orchestrate (Ghost Data Still Exists).
Produces code/explain/explain.jsonl mapping every output step to:
- rule_id
- evidence_id / evidence source
- linking_identifier (email, user_id, phone, hash)
"""

import os
import csv
import json
from typing import Dict, List, Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def generate_explainability(output_csv_path: str = "output.csv", explain_jsonl_path: str = "code/explain/explain.jsonl"):
    os.makedirs(os.path.dirname(explain_jsonl_path), exist_ok=True)
    
    # Load user identities
    user_map = {}
    with open("dataset/user_identities.csv", "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            user_map[r["user_id"]] = r["email"]

    # Load deletion requests
    req_map = {}
    with open("dataset/deletion_requests.csv", "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            req_map[r["case_id"]] = r

    # Load deletion rules
    rules_by_op = {
        "REPORT_REMAINING_RECORD": "RULE_DELETE_DIRECT_PII",
        "REPORT_EXPOSED_PII": "RULE_REDACT_IDENTIFIERS",
        "REPORT_ACTIVE_DATA_FLOW": "RULE_HALT_REPLICATION_FLOWS",
        "REPORT_RESTORE_RISK": "RULE_BLOCK_RESTORE_PATHS",
        "DISABLE_DATA_FLOW": "RULE_DISABLE_INTEGRATION_SYNC",
        "BLOCK_RESTORE": "RULE_ISOLATE_BACKUP_RESTORE",
        "DELETE_RECORD": "RULE_PURGE_PRIMARY_STORAGE",
        "REDACT_RECORD": "RULE_SCRUB_CONTACT_FIELDS",
        "ANONYMIZE_RECORD": "RULE_IRREVERSIBLE_PSEUDONYMIZATION",
        "VERIFY_RECORD_ABSENT": "RULE_VERIFY_ABSENCE_PROOF",
        "VERIFY_RECORD_PRESENT": "RULE_VERIFY_COMPLIANT_RETENTION",
        "VERIFY_RECORD_REDACTED": "RULE_VERIFY_PII_REMOVAL",
        "VERIFY_RECORD_ANONYMIZED": "RULE_VERIFY_ANONYMIZATION",
        "VERIFY_DATA_FLOW_DISABLED": "RULE_VERIFY_FLOW_INACTIVE",
        "VERIFY_RESTORE_BLOCKED": "RULE_VERIFY_RESTORE_BLOCKED",
    }

    records_written = 0
    with open(output_csv_path, "r", encoding="utf-8") as inf, \
         open(explain_jsonl_path, "w", encoding="utf-8") as outf:
        reader = csv.DictReader(inf)
        for r in reader:
            cid = r["case_id"]
            req = req_map.get(cid, {})
            steps = json.loads(r["steps_json"])
            for s in steps:
                op = s.get("operation", "")
                rule_id = rules_by_op.get(op, "RULE_GENERAL_POLICY")
                entry = {
                    "case_id": cid,
                    "step_no": s.get("step_no", 1),
                    "phase": s.get("phase", ""),
                    "system_id": s.get("system_id", ""),
                    "resource_id": s.get("resource_id", ""),
                    "operation": op,
                    "state": s.get("state", ""),
                    "rule_id": rule_id,
                    "evidence_id": s.get("evidence_id", ""),
                    "linking_identifier": req.get("email", ""),
                }
                outf.write(json.dumps(entry) + "\n")
                records_written += 1

    print(f"Generated {records_written} explainability records in {explain_jsonl_path}.")
    return records_written

if __name__ == "__main__":
    generate_explainability()
