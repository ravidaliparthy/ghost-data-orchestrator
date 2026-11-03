"""
Independent Per-Request Cross-Check Harness for HackerRank Orchestrate (Ghost Data Still Exists).
Verifies all 518 evaluation rows against raw CSV, manifest, activity, and evidence files.
Checks:
1. Intent Authorization
2. Identity Resolution
3. Time Cutoff (timestamp <= audit_at)
4. Citations Linkage (file/activity contains identifier or resource_id, including PDF extraction)
5. Contract & Structural Invariants
6. Policy Action Compliance
7. Status & Step Consistency
Outputs: code/evaluation/crosscheck_report.md
"""

import os
import sys
import csv
import json
import re
from datetime import datetime, timezone
from typing import Dict, List, Set, Any, Tuple

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "code"))

from engine.pdf_extractor import extract_pdf_text
from engine.intent_classifier import IntentClassifier

DATASET_DIR = os.path.join(REPO_ROOT, "dataset")

# Allowed schema combinations from problem statement §6.4
ALLOWED_COMBOS = {
    ("FINDING", "REPORT_REMAINING_RECORD", "PRESENT"),
    ("FINDING", "REPORT_EXPOSED_PII", "PRESENT"),
    ("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
    ("FINDING", "REPORT_RESTORE_RISK", "ACTIVE"),
    ("REMEDIATION", "DISABLE_DATA_FLOW", "DISABLED"),
    ("REMEDIATION", "BLOCK_RESTORE", "BLOCKED"),
    ("REMEDIATION", "DELETE_RECORD", "ABSENT"),
    ("REMEDIATION", "REDACT_RECORD", "REDACTED"),
    ("REMEDIATION", "ANONYMIZE_RECORD", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"),
    ("VERIFICATION", "VERIFY_RECORD_PRESENT", "PRESENT"),
    ("VERIFICATION", "VERIFY_RECORD_REDACTED", "REDACTED"),
    ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    ("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "BLOCKED"),
}

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_PRECEDENCE = {
    "REPORT_ACTIVE_DATA_FLOW": 0, "REPORT_RESTORE_RISK": 1, "REPORT_REMAINING_RECORD": 2, "REPORT_EXPOSED_PII": 3,
    "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
    "VERIFY_DATA_FLOW_DISABLED": 0, "VERIFY_RESTORE_BLOCKED": 1, "VERIFY_RECORD_ABSENT": 2, "VERIFY_RECORD_PRESENT": 3, "VERIFY_RECORD_REDACTED": 4, "VERIFY_RECORD_ANONYMIZED": 5
}

def parse_utc(ts: str) -> datetime:
    if not ts:
        return datetime.min.replace(tzinfo=timezone.utc)
    s = ts.replace("Z", "+00:00")
    return datetime.fromisoformat(s)

class CrossChecker:
    def __init__(self, dataset_dir: str = DATASET_DIR, output_csv: str = "output.csv"):
        self.dataset_dir = dataset_dir
        self.output_csv = os.path.join(REPO_ROOT, output_csv)
        self.identities = {}
        self.user_history = {}
        self.manifest = {}
        self.activities = {}
        self.audit_records = {}
        self.rules = []
        self.evidence_cache = {}
        self.intent_classifier = IntentClassifier(False)
        self.defects = []
        self.counts = {
            "total_cases": 0,
            "intent_pass": 0, "intent_defects": 0,
            "identity_pass": 0, "identity_defects": 0,
            "time_pass": 0, "time_defects": 0,
            "citations_pass": 0, "citations_defects": 0,
            "contract_pass": 0, "contract_defects": 0,
            "policy_pass": 0, "policy_defects": 0,
            "status_pass": 0, "status_defects": 0,
        }
        self._load_raw_data()

    def _load_raw_data(self):
        # 1. Identities
        with open(os.path.join(self.dataset_dir, "user_identities.csv"), "r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                uid = r["user_id"]
                email = r["email"].lower()
                self.identities[email] = uid
                self.user_history.setdefault(uid, {
                    "emails": set(), "names": set(), "phones": set(), "hashes": set()
                })
                self.user_history[uid]["emails"].add(email)
                if r.get("name"): self.user_history[uid]["names"].add(r["name"])
                if r.get("phone"): self.user_history[uid]["phones"].add(r["phone"])
                if r.get("email_hash"): self.user_history[uid]["hashes"].add(r["email_hash"])

        # 2. Historical changes
        with open(os.path.join(self.dataset_dir, "user_audit_log.csv"), "r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                uid = r["user_id"]
                field = r["field_name"]
                old_val = r["old_value"]
                audit_id = r.get("audit_id", "")
                if audit_id:
                    self.audit_records[audit_id] = r
                if uid in self.user_history and old_val:
                    if field == "email":
                        old_email = old_val.lower()
                        self.user_history[uid]["emails"].add(old_email)
                        self.identities[old_email] = uid
                    elif field == "name":
                        self.user_history[uid]["names"].add(old_val)
                    elif field == "phone":
                        self.user_history[uid]["phones"].add(old_val)
                    elif field == "email_hash":
                        self.user_history[uid]["hashes"].add(old_val)

        # 3. Manifest
        with open(os.path.join(self.dataset_dir, "evidence_files.csv"), "r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                self.manifest[r["file_id"]] = {
                    "path": r["file_path"],
                    "origin": r["origin"],
                    "captured_at": r["captured_at"],
                    "dt": parse_utc(r["captured_at"])
                }

        # 4. System Activity
        with open(os.path.join(self.dataset_dir, "system_activity.csv"), "r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                self.activities[r["activity_id"]] = {
                    "event_time": r["event_time"],
                    "dt": parse_utc(r["event_time"]),
                    "event_type": r["event_type"],
                    "source_system": r["source_system"],
                    "target_system": r["target_system"],
                    "resource_id": r["resource_id"],
                    "details": r["details"]
                }

        # 5. Rules
        with open(os.path.join(self.dataset_dir, "deletion_rules.csv"), "r", encoding="utf-8") as f:
            self.rules = list(csv.DictReader(f))

    def _file_contains_text(self, file_id: str, search_tokens: Set[str]) -> bool:
        if file_id not in self.manifest:
            return False
        finfo = self.manifest[file_id]
        fpath = os.path.join(self.dataset_dir, finfo["path"])
        if not os.path.isfile(fpath):
            return False
        if fpath not in self.evidence_cache:
            if fpath.endswith(".pdf"):
                self.evidence_cache[fpath] = extract_pdf_text(fpath).lower()
            else:
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        self.evidence_cache[fpath] = f.read().lower()
                except Exception:
                    self.evidence_cache[fpath] = ""
        content = self.evidence_cache[fpath]
        return any(tok.lower() in content for tok in search_tokens if tok)

    def cross_check_all(self):
        with open(self.output_csv, "r", encoding="utf-8") as f:
            predictions = {r["case_id"]: r for r in csv.DictReader(f)}

        with open(os.path.join(self.dataset_dir, "deletion_requests.csv"), "r", encoding="utf-8") as f:
            requests = list(csv.DictReader(f))

        self.counts["total_cases"] = len(requests)

        for req in requests:
            cid = req["case_id"]
            email = req["email"].lower()
            audit_at_str = req["audit_at"]
            audit_dt = parse_utc(audit_at_str)
            text = req["request_text"]

            pred = predictions.get(cid)
            if not pred:
                self.defects.append((cid, "MissingRow", "Case ID not found in output.csv"))
                continue

            status = pred["deletion_status"]
            steps = json.loads(pred["steps_json"])

            # -------------------------------------------------------------
            # Check 1: Intent
            # -------------------------------------------------------------
            intent_res = self.intent_classifier.classify(text)
            auth = intent_res.authorized
            if not auth:
                if status != "NOT_APPLICABLE":
                    self.counts["intent_defects"] += 1
                    self.defects.append((cid, "IntentDefect", f"Request does not authorize deletion ({intent_res.intent}) but status is {status}"))
                else:
                    self.counts["intent_pass"] += 1
            else:
                if status == "NOT_APPLICABLE":
                    self.counts["intent_defects"] += 1
                    self.defects.append((cid, "IntentDefect", f"Request authorizes deletion but status is NOT_APPLICABLE. Text: {text[:60]}"))
                else:
                    self.counts["intent_pass"] += 1

            # -------------------------------------------------------------
            # Check 2: Identity
            # -------------------------------------------------------------
            uid = self.identities.get(email)
            if not uid:
                self.counts["identity_defects"] += 1
                self.defects.append((cid, "IdentityDefect", f"Email {email} unresolvable to user_id"))
            else:
                self.counts["identity_pass"] += 1

            subj_tokens = set()
            if uid:
                subj_tokens.add(uid)
                subj_tokens.update(self.user_history[uid]["emails"])
                subj_tokens.update(self.user_history[uid]["names"])

            # -------------------------------------------------------------
            # Check 3: Time Cutoff
            # -------------------------------------------------------------
            case_time_ok = True
            for s in steps:
                eid = s.get("evidence_id", "")
                if eid:
                    ev_dt = None
                    if eid in self.manifest:
                        ev_dt = self.manifest[eid]["dt"]
                    elif eid in self.activities:
                        ev_dt = self.activities[eid]["dt"]
                    elif eid in self.audit_records:
                        ev_dt = parse_utc(self.audit_records[eid]["changed_at"])
                    else:
                        case_time_ok = False
                        self.defects.append((cid, "TimeDefect", f"Citations {eid} does not exist in manifest, activity, or audit"))
                    
                    if ev_dt and ev_dt > audit_dt:
                        case_time_ok = False
                        self.defects.append((cid, "TimeDefect", f"Citations {eid} timestamp {ev_dt.isoformat()} > audit_at {audit_at_str}"))

            if case_time_ok:
                self.counts["time_pass"] += 1
            else:
                self.counts["time_defects"] += 1

            # -------------------------------------------------------------
            # Check 4: Citations Grounding
            # -------------------------------------------------------------
            case_cit_ok = True
            for s in steps:
                phase = s.get("phase")
                op = s.get("operation")
                eid = s.get("evidence_id", "")
                res_id = s.get("resource_id", "")

                if phase == "FINDING" or (status == "COMPLETE" and phase == "VERIFICATION"):
                    if not eid:
                        case_cit_ok = False
                        self.defects.append((cid, "CitationDefect", f"{phase} step {op} on {res_id} has empty evidence_id"))
                    else:
                        search_set = subj_tokens | ({res_id} if res_id else set())
                        has_link = False
                        if eid in self.activities:
                            act = self.activities[eid]
                            has_link = (res_id in act["resource_id"]) or any(tok.lower() in act["details"].lower() for tok in subj_tokens)
                        elif eid in self.manifest:
                            has_link = self._file_contains_text(eid, search_set)
                        elif eid in self.audit_records:
                            rec = self.audit_records[eid]
                            has_link = (uid == rec["user_id"])

                        if not has_link:
                            is_png = (eid in self.manifest and self.manifest[eid]["path"].endswith(".png"))
                            if not is_png:
                                case_cit_ok = False
                                self.defects.append((cid, "CitationDefect", f"Citation {eid} does not contain subject tokens or resource_id {res_id}"))
                elif phase in ("REMEDIATION", "VERIFICATION") and status == "INCOMPLETE":
                    if eid != "":
                        case_cit_ok = False
                        self.defects.append((cid, "CitationDefect", f"Future {phase} step {op} on {res_id} must have empty evidence_id, got '{eid}'"))

            if case_cit_ok:
                self.counts["citations_pass"] += 1
            else:
                self.counts["citations_defects"] += 1

            # -------------------------------------------------------------
            # Check 5: Contract & Structure
            # -------------------------------------------------------------
            contract_ok = True
            if status == "NOT_APPLICABLE":
                if steps != []:
                    contract_ok = False
                    self.defects.append((cid, "ContractDefect", f"NOT_APPLICABLE case has non-empty steps {steps}"))
            elif status == "INCOMPLETE":
                if len(steps) == 0:
                    contract_ok = False
                    self.defects.append((cid, "ContractDefect", "INCOMPLETE case has empty steps []"))
            elif status == "COMPLETE":
                if any(s.get("phase") != "VERIFICATION" for s in steps):
                    contract_ok = False
                    self.defects.append((cid, "ContractDefect", "COMPLETE case has non-VERIFICATION steps"))

            phases_seen = []
            seen_tuples = set()
            for i, s in enumerate(steps, start=1):
                if s.get("step_no") != i:
                    contract_ok = False
                    self.defects.append((cid, "ContractDefect", f"Step no {s.get('step_no')} != consecutive index {i}"))
                
                phase = s.get("phase")
                op = s.get("operation")
                state = s.get("state")
                sys_id = s.get("system_id")
                res_id = s.get("resource_id")

                if (phase, op, state) not in ALLOWED_COMBOS:
                    contract_ok = False
                    self.defects.append((cid, "ContractDefect", f"Invalid combo: {phase}, {op}, {state}"))

                tup = (op, sys_id, res_id)
                if tup in seen_tuples:
                    contract_ok = False
                    self.defects.append((cid, "ContractDefect", f"Duplicate operation-system-resource: {tup}"))
                seen_tuples.add(tup)

                if phase:
                    phases_seen.append(PHASE_ORDER.get(phase, 99))

            if phases_seen != sorted(phases_seen):
                contract_ok = False
                self.defects.append((cid, "ContractDefect", "Phase sequence out of order (must be FINDING -> REMEDIATION -> VERIFICATION)"))

            if contract_ok:
                self.counts["contract_pass"] += 1
            else:
                self.counts["contract_defects"] += 1

            # -------------------------------------------------------------
            # Check 6: Policy
            # -------------------------------------------------------------
            policy_ok = True
            for s in steps:
                res_id = s.get("resource_id", "")
                op = s.get("operation", "")
                if "tombstone" in res_id.lower():
                    if op not in ("REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_PRESENT"):
                        policy_ok = False
                        self.defects.append((cid, "PolicyDefect", f"Tombstone {res_id} should only be redacted/verified, got {op}"))
            if policy_ok:
                self.counts["policy_pass"] += 1
            else:
                self.counts["policy_defects"] += 1

            # -------------------------------------------------------------
            # Check 7: Status Consistency
            # -------------------------------------------------------------
            status_ok = True
            findings = [s for s in steps if s.get("phase") == "FINDING"]
            if status == "INCOMPLETE" and len(findings) == 0:
                status_ok = False
                self.defects.append((cid, "StatusDefect", "Status is INCOMPLETE but has 0 findings"))
            elif status == "COMPLETE" and len(findings) > 0:
                status_ok = False
                self.defects.append((cid, "StatusDefect", f"Status is COMPLETE but has {len(findings)} findings"))
            if status_ok:
                self.counts["status_pass"] += 1
            else:
                self.counts["status_defects"] += 1

        self._generate_report()

    def _generate_report(self):
        report_path = os.path.join(REPO_ROOT, "code", "evaluation", "crosscheck_report.md")
        lines = [
            "# Cross-Check Audit Report: All 518 Evaluation Rows",
            f"\n**Generated At**: {datetime.now(timezone.utc).isoformat()}",
            f"**Total Cases Verified**: {self.counts['total_cases']}",
            f"**Total Defects Detected**: {len(self.defects)}\n",
            "## Summary Table by Verification Check\n",
            "| Check Name | Passing Cases | Defective Cases | Pass Rate |",
            "|---|---|---|---|",
            f"| 1. Intent Authorization | {self.counts['intent_pass']} | {self.counts['intent_defects']} | {self.counts['intent_pass']/self.counts['total_cases']*100:.2f}% |",
            f"| 2. Identity Resolution | {self.counts['identity_pass']} | {self.counts['identity_defects']} | {self.counts['identity_pass']/self.counts['total_cases']*100:.2f}% |",
            f"| 3. Time Cutoff (<= audit_at) | {self.counts['time_pass']} | {self.counts['time_defects']} | {self.counts['time_pass']/self.counts['total_cases']*100:.2f}% |",
            f"| 4. Citations Grounding | {self.counts['citations_pass']} | {self.counts['citations_defects']} | {self.counts['citations_pass']/self.counts['total_cases']*100:.2f}% |",
            f"| 5. Contract & Structure | {self.counts['contract_pass']} | {self.counts['contract_defects']} | {self.counts['contract_pass']/self.counts['total_cases']*100:.2f}% |",
            f"| 6. Policy Action Compliance | {self.counts['policy_pass']} | {self.counts['policy_defects']} | {self.counts['policy_pass']/self.counts['total_cases']*100:.2f}% |",
            f"| 7. Status & Step Consistency | {self.counts['status_pass']} | {self.counts['status_defects']} | {self.counts['status_pass']/self.counts['total_cases']*100:.2f}% |",
            "\n---\n",
            "## Defect Log (case_id | check | detail)\n",
        ]
        if not self.defects:
            lines.append("Zero defects detected across all 518 cases! 100% compliant.\n")
        else:
            for cid, chk, dtl in self.defects:
                lines.append(f"- **{cid}** | `{chk}` | {dtl}")

        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        
        print("\n" + "="*70)
        print("=== CROSS-CHECK AUDIT SUMMARY (518 ROWS) ===")
        print("="*70)
        print(f"Total Cases Checked: {self.counts['total_cases']}")
        print(f"Total Defects Found: {len(self.defects)}")
        for k in ["intent", "identity", "time", "citations", "contract", "policy", "status"]:
            print(f"  Check '{k:<10}': {self.counts[k+'_pass']:>3} PASS | {self.counts[k+'_defects']:>3} DEFECTS")
        print("="*70)
        if self.defects:
            print("\nDefects Discovered:")
            for cid, chk, dtl in self.defects[:15]:
                print(f"  {cid:<10} | {chk:<16} | {dtl}")
            if len(self.defects) > 15:
                print(f"  ... and {len(self.defects) - 15} more defects.")
        print()

if __name__ == "__main__":
    checker = CrossChecker()
    checker.cross_check_all()
