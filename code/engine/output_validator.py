"""OutputValidator - validates output.csv against the strict contract."""
import csv
import json
import os

ALLOWED_PAIRS = {
    ("REPORT_REMAINING_RECORD", "PRESENT"),
    ("REPORT_EXPOSED_PII", "PRESENT"),
    ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
    ("REPORT_RESTORE_RISK", "ACTIVE"),
    ("DISABLE_DATA_FLOW", "DISABLED"),
    ("BLOCK_RESTORE", "BLOCKED"),
    ("DELETE_RECORD", "ABSENT"),
    ("REDACT_RECORD", "REDACTED"),
    ("ANONYMIZE_RECORD", "ANONYMIZED"),
    ("VERIFY_RECORD_ABSENT", "ABSENT"),
    ("VERIFY_RECORD_PRESENT", "PRESENT"),
    ("VERIFY_RECORD_REDACTED", "REDACTED"),
    ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
}

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_PREC = {
    "REPORT_REMAINING_RECORD": 1, "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3, "REPORT_RESTORE_RISK": 4,
    "DISABLE_DATA_FLOW": 5, "BLOCK_RESTORE": 6,
    "DELETE_RECORD": 7, "REDACT_RECORD": 8, "ANONYMIZE_RECORD": 9,
    "VERIFY_RECORD_ABSENT": 10, "VERIFY_RECORD_PRESENT": 11,
    "VERIFY_RECORD_REDACTED": 12, "VERIFY_RECORD_ANONYMIZED": 13,
    "VERIFY_DATA_FLOW_DISABLED": 14, "VERIFY_RESTORE_BLOCKED": 15,
}
STEP_KEYS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}


def _parse_utc(s):
    from .common import parse_utc as pu
    return pu(s)


class OutputValidator:
    def __init__(self, dataset_dir, output_path):
        self.dataset_dir = dataset_dir
        self.output_path = output_path
        self.errors = []

    def _err(self, case_id, msg):
        self.errors.append(f"{case_id}: {msg}")

    def validate(self):
        self.errors = []
        req_path = os.path.join(self.dataset_dir, "deletion_requests.csv")
        with open(req_path, newline="", encoding="utf-8") as f:
            expected_ids = [r["case_id"] for r in csv.DictReader(f)]
        expected_ids_sorted = sorted(expected_ids)

        if not os.path.exists(self.output_path):
            self.errors.append("output.csv missing")
            return False
        with open(self.output_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames != ["case_id", "deletion_status", "steps_json"]:
                self.errors.append(f"bad header: {reader.fieldnames}")
            rows = list(reader)

        if len(rows) != len(expected_ids):
            self.errors.append(f"row count {len(rows)} != {len(expected_ids)}")

        ids = [r["case_id"] for r in rows]
        if ids != expected_ids_sorted:
            for i, (a, b) in enumerate(zip(ids, expected_ids_sorted)):
                if a != b:
                    self._err(a if i < len(ids) else "?", f"sort/coverage mismatch at {i}: got {a} expected {b}")
                    break
            if len(ids) != len(expected_ids_sorted):
                self.errors.append("id count mismatch")

        valid_statuses = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
        for r in rows:
            cid = r["case_id"]
            status = r["deletion_status"]
            if status not in valid_statuses:
                self._err(cid, f"invalid status {status}")
            try:
                steps = json.loads(r["steps_json"])
            except Exception as e:
                self._err(cid, f"invalid json: {e}")
                continue
            if not isinstance(steps, list):
                self._err(cid, "steps_json not array")
                continue
            if status == "NOT_APPLICABLE":
                if steps != []:
                    self._err(cid, "NOT_APPLICABLE must have []")
                continue
            prev_phase = -1
            for i, st in enumerate(steps, start=1):
                if not isinstance(st, dict):
                    self._err(cid, f"step {i} not object")
                    continue
                if set(st.keys()) != STEP_KEYS:
                    self._err(cid, f"step {i} keys {set(st.keys())}")
                if st.get("step_no") != i:
                    self._err(cid, f"step {i} step_no {st.get('step_no')}")
                pair = (st.get("operation"), st.get("state"))
                if pair not in ALLOWED_PAIRS:
                    self._err(cid, f"step {i} bad pair {pair}")
                ph = st.get("phase")
                if ph not in PHASE_ORDER:
                    self._err(cid, f"step {i} bad phase {ph}")
                elif PHASE_ORDER[ph] < prev_phase:
                    self._err(cid, f"step {i} phase order violation")
                if ph in PHASE_ORDER:
                    prev_phase = max(prev_phase, PHASE_ORDER[ph])
            for phase in ("FINDING", "REMEDIATION", "VERIFICATION"):
                ph_steps = [s for s in steps if s.get("phase") == phase]
                keys = [(OP_PREC.get(s.get("operation"), 999), s.get("system_id", ""), s.get("resource_id", "")) for s in ph_steps]
                if keys != sorted(keys):
                    self._err(cid, f"phase {phase} not sorted")
            for st in steps:
                if st.get("phase") == "REMEDIATION" and st.get("evidence_id") != "":
                    self._err(cid, f"remediation step {st.get('step_no')} non-empty evidence_id")

        audit_map = {}
        with open(req_path, newline="", encoding="utf-8") as f:
            for r2 in csv.DictReader(f):
                audit_map[r2["case_id"]] = r2["audit_at"]
        manifest = {}
        man_path = os.path.join(self.dataset_dir, "evidence_files.csv")
        with open(man_path, newline="", encoding="utf-8") as f:
            for r2 in csv.DictReader(f):
                manifest[r2["file_id"]] = r2["captured_at"]
        activity_times = {}
        act_path = os.path.join(self.dataset_dir, "system_activity.csv")
        with open(act_path, newline="", encoding="utf-8") as f:
            for r2 in csv.DictReader(f):
                activity_times[r2["activity_id"]] = r2["event_time"]
        audit_times = {}
        audit_path = os.path.join(self.dataset_dir, "user_audit_log.csv")
        with open(audit_path, newline="", encoding="utf-8") as f:
            for r2 in csv.DictReader(f):
                audit_times[r2["audit_id"]] = r2["event_time"]

        def _cap_time(eid):
            if eid in manifest:
                return _parse_utc(manifest[eid])
            if eid in activity_times:
                return _parse_utc(activity_times[eid])
            if eid in audit_times:
                return _parse_utc(audit_times[eid])
            return None

        def _known(eid):
            return eid in manifest or eid in activity_times or eid in audit_times

        for r in rows:
            cid = r["case_id"]
            try:
                steps = json.loads(r["steps_json"])
            except Exception:
                continue
            if not isinstance(steps, list):
                continue
            audit_at = audit_map.get(cid)
            audit_dt = _parse_utc(audit_at) if audit_at else None
            for st in steps:
                eid = st.get("evidence_id", "")
                if eid == "":
                    continue
                if not _known(eid):
                    self._err(cid, f"unknown evidence_id {eid}")
                    continue
                cap = _cap_time(eid)
                if audit_dt is not None and cap is not None and cap > audit_dt:
                    self._err(cid, f"evidence {eid} captured after audit_at")

        return len(self.errors) == 0

    def report(self):
        if not self.errors:
            return "OutputValidator: PASS"
        return "OutputValidator: FAIL\n" + "\n".join(self.errors[:50]) + (f"\n... {len(self.errors)-50} more" if len(self.errors) > 50 else "")
