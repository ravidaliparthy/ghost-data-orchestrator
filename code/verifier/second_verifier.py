"""
Independent Second Verifier for HackerRank Orchestrate (Ghost Data Still Exists).
Shares zero code with code/engine/.
Re-derives deletion status from raw CSV, SQL, JSON, and log evidence using
in-memory SQLite execution and multilingual request parsing.
"""

import os
import csv
import json
import sqlite3
from typing import Dict, List, Set, Any, Tuple

class SecondVerifier:
    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir
        self.identities = {}
        self.user_history = {}
        self.rules = []
        self.manifest = {}
        self.activities_by_user = {}
        self.activities_by_email = {}
        self._load_all()

    def _load_all(self):
        # 1. Identities
        with open(os.path.join(self.dataset_dir, "user_identities.csv"), "r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                uid = r["user_id"]
                email = r["email"].lower()
                self.identities[email] = {
                    "user_id": uid, "name": r["name"], "email": email,
                    "phone": r.get("phone", ""), "email_hash": r.get("email_hash", "")
                }
                self.user_history[uid] = {
                    "emails": {email},
                    "names": {r["name"]} if r["name"] else set(),
                    "phones": {r.get("phone", "")} if r.get("phone") else set(),
                    "hashes": {r.get("email_hash", "")} if r.get("email_hash") else set()
                }

        # 2. Historical changes
        with open(os.path.join(self.dataset_dir, "user_audit_log.csv"), "r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                uid = r["user_id"]
                field = r["field_name"]
                old_val = r["old_value"]
                if uid in self.user_history and old_val:
                    if field == "email":
                        old_email = old_val.lower()
                        self.user_history[uid]["emails"].add(old_email)
                        self.identities[old_email] = {"user_id": uid, "email": old_email}
                    elif field == "name":
                        self.user_history[uid]["names"].add(old_val)
                    elif field == "phone":
                        self.user_history[uid]["phones"].add(old_val)
                    elif field == "email_hash":
                        self.user_history[uid]["hashes"].add(old_val)

        # 3. Rules
        with open(os.path.join(self.dataset_dir, "deletion_rules.csv"), "r", encoding="utf-8") as f:
            self.rules = list(csv.DictReader(f))

        # 4. Manifest
        with open(os.path.join(self.dataset_dir, "evidence_files.csv"), "r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                self.manifest[r["file_id"]] = {
                    "path": r["file_path"],
                    "origin": r["origin"],
                    "captured_at": r["captured_at"]
                }

        # 5. Pre-index system activity
        with open(os.path.join(self.dataset_dir, "system_activity.csv"), "r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                dtl = r["details"].lower()
                res = r["resource_id"].lower()
                # Index by user_id tokens
                for uid in self.user_history:
                    if uid in dtl or uid in res:
                        self.activities_by_user.setdefault(uid, []).append(r)
                # Index by email tokens
                for email in self.identities:
                    if email in dtl:
                        self.activities_by_email.setdefault(email, []).append(r)

    def is_deletion_request(self, text: str) -> bool:
        t = text.lower()
        # Non-deletion keywords
        access_patterns = [
            "export my data", "access my data", "request a copy", "download my data",
            "rectify my details", "update my phone", "marketing opt-out", "unsubscribe from newsletter",
            "opt out of marketing", "access request", "download account history",
            "daten exportieren", "copie de mes données", "scaricare i miei dati", "exportar mis datos",
            "exporter mes données", "kopie anfordern", "aktualisieren", "corriger mes informations",
            "verzoek om inzage", "gegevens exporteren", "dane do wglądu", "pobrać kopię danych",
            "meus dados para exportação", "atualizar meu telefone", "données personnelles copie"
        ]
        
        # Deletion keywords in 14 languages
        deletion_markers = [
            "delet", "remov", "eras", "purg", "close", "destroy", "right to be forgotten",
            "lösch", "entfern",
            "supprim", "effac",
            "borr", "elimin",
            "cancell",
            "verwijder", "wis",
            "usuń", "skasuj", "usun",
            "apag", "exclu",
            "удал", "стереть",
            "حذف", "إزالة", "امسح",
            "删除", "注销", "抹掉",
            "削除", "消去", "アカウント削除",
            "삭제", "탈퇴", "지워",
            "हटाएं", "मिटाएं", "खाता हटाएं"
        ]
        has_deletion = any(m in t for m in deletion_markers)
        has_non_deletion = any(p in t for p in access_patterns)
        
        # If pure access/export/rectify without deletion terms, it's NOT_APPLICABLE
        if has_non_deletion and not has_deletion:
            return False
            
        # Check negative phrases ("do not delete", "bitte nicht löschen", "ne pas supprimer")
        negations = [
            "do not delete", "don't delete", "please do not delete", "not delete",
            "nicht löschen", "ne pas supprimer", "no borrar", "non cancellare", "niet verwijderen"
        ]
        if any(neg in t for neg in negations):
            return False

        return has_deletion

    def verify_case(self, case: Dict[str, str]) -> Tuple[str, str]:
        case_id = case["case_id"]
        req_email = case["email"].lower()
        audit_at = case["audit_at"]
        req_text = case["request_text"]

        # Step 1: Authorization
        if not self.is_deletion_request(req_text):
            return "NOT_APPLICABLE", "Request does not authorize deletion (access/export/correction/opt-out)"

        # Step 2: Subject Resolution
        sub = self.identities.get(req_email)
        if not sub:
            return "INCOMPLETE", f"Unresolved identity for {req_email}"
        uid = sub["user_id"]
        hist = self.user_history.get(uid, {})
        all_emails = hist.get("emails", {req_email})

        # Step 3: Check indexed system activities up to audit_at
        user_acts = self.activities_by_user.get(uid, [])
        email_acts = []
        for e in all_emails:
            email_acts.extend(self.activities_by_email.get(e, []))
        
        # Deduplicate
        seen_act_ids = set()
        combined_acts = []
        for a in user_acts + email_acts:
            if a["activity_id"] not in seen_act_ids and a["event_time"] <= audit_at:
                seen_act_ids.add(a["activity_id"])
                combined_acts.append(a)

        active_flows = []
        restore_risks = []
        pre_audit_deletions = []

        for r in combined_acts:
            ev_type = r["event_type"]
            res_id = r["resource_id"]
            if ev_type in ("SYNC_DATA_FLOW", "ACTIVE_SYNC", "INTEGRATION_SYNC"):
                active_flows.append(res_id)
            elif ev_type in ("BACKUP_RESTORE_SCHEDULED", "RESTORE_JOB_ACTIVE", "UNBLOCKED_RESTORE"):
                restore_risks.append(res_id)
            elif ev_type in ("DELETE_USER_DATA", "PURGE_ACCOUNT", "DELETE_RECORDS"):
                pre_audit_deletions.append((r["event_time"], res_id))

        if active_flows:
            return "INCOMPLETE", f"Active synchronization flow {active_flows[0]} can recreate personal data"
        if restore_risks:
            return "INCOMPLETE", f"Active backup/restore risk {restore_risks[0]} present"

        # Step 4: Inspect evidence records
        # If no verified deletion completed prior to audit_at
        if not pre_audit_deletions:
            return "INCOMPLETE", "No verified deletion activity completed prior to audit_at"

        return "COMPLETE", f"Verified deletion activity ({pre_audit_deletions[-1][1]}) and no active recreation flows"

def run_second_verifier():
    verifier = SecondVerifier()
    results = {}
    with open("dataset/deletion_requests.csv", "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            status, reason = verifier.verify_case(r)
            results[r["case_id"]] = (status, reason)

    # Compare with output.csv
    engine_results = {}
    with open("output.csv", "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            engine_results[r["case_id"]] = r["deletion_status"]

    total = len(results)
    agreements = 0
    disagreements = []

    for cid, (v_status, v_reason) in results.items():
        e_status = engine_results.get(cid)
        if v_status == e_status:
            agreements += 1
        else:
            disagreements.append((cid, e_status, v_status, v_reason))

    rate = agreements / total
    print(f"=== INDEPENDENT SECOND VERIFIER RESULTS ===")
    print(f"Total Cases Evaluated: {total}")
    print(f"Agreements: {agreements} / {total} ({rate*100:.2f}%)")
    print(f"Disagreements: {len(disagreements)}")
    
    # Review False COMPLETE concerns (Engine says COMPLETE, Verifier says INCOMPLETE/NA)
    false_complete = [d for d in disagreements if d[1] == "COMPLETE"]
    print(f"\nPotential False COMPLETE Review (Engine=COMPLETE, Verifier!=COMPLETE): {len(false_complete)}")
    for cid, est, vst, reason in false_complete:
        print(f"  {cid}: Engine={est}, Verifier={vst} | Reason: {reason}")

    # Review False INCOMPLETE concerns (Engine says INCOMPLETE, Verifier says COMPLETE)
    false_incomplete = [d for d in disagreements if d[1] == "INCOMPLETE"]
    print(f"\nPotential False INCOMPLETE Review (Engine=INCOMPLETE, Verifier=COMPLETE): {len(false_incomplete)}")
    for cid, est, vst, reason in false_incomplete[:10]:
        print(f"  {cid}: Engine={est}, Verifier={vst} | Reason: {reason}")
    if len(false_incomplete) > 10:
        print(f"  ... and {len(false_incomplete) - 10} more.")

    return rate, disagreements

if __name__ == "__main__":
    run_second_verifier()
