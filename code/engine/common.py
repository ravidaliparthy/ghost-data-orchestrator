"""
Ghost Data Still Exists — Data Deletion Verification Engine
Common utilities module.

Security principles applied in this layer:
- No secrets, API keys, or credentials stored or logged.
- All timestamps normalized to UTC; naive datetimes rejected.
- Deterministic sorting and serialization (no randomness, no sets for output order).
- Input validation: malformed timestamps, empty IDs, and non-UTF8 are handled safely.
- No real PII written to logs or side traces (only resource_id / file_id / case_id references).
"""

import csv
import json
import re
import hashlib
import unicodedata
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

EPOCH_MIN = datetime.min.replace(tzinfo=timezone.utc)
EPOCH_MAX = datetime.max.replace(tzinfo=timezone.utc)

ALLOWED_OPERATION_STATES: Dict[str, List[str]] = {
    "REPORT_REMAINING_RECORD": ["PRESENT"],
    "REPORT_EXPOSED_PII": ["PRESENT"],
    "REPORT_ACTIVE_DATA_FLOW": ["ACTIVE"],
    "REPORT_RESTORE_RISK": ["ACTIVE"],
    "DISABLE_DATA_FLOW": ["DISABLED"],
    "BLOCK_RESTORE": ["BLOCKED"],
    "DELETE_RECORD": ["ABSENT"],
    "REDACT_RECORD": ["REDACTED"],
    "ANONYMIZE_RECORD": ["ANONYMIZED"],
    "VERIFY_RECORD_ABSENT": ["ABSENT"],
    "VERIFY_RECORD_PRESENT": ["PRESENT"],
    "VERIFY_RECORD_REDACTED": ["REDACTED"],
    "VERIFY_RECORD_ANONYMIZED": ["ANONYMIZED"],
    "VERIFY_DATA_FLOW_DISABLED": ["DISABLED"],
    "VERIFY_RESTORE_BLOCKED": ["BLOCKED"],
}

VALID_PHASES = ["FINDING", "REMEDIATION", "VERIFICATION"]
VALID_STATUSES = ["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"]

OPERATION_PRECEDENCE: Dict[str, int] = {
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,
    "DISABLE_DATA_FLOW": 1,
    "BLOCK_RESTORE": 2,
    "DELETE_RECORD": 3,
    "REDACT_RECORD": 4,
    "ANONYMIZE_RECORD": 5,
    "VERIFY_RECORD_ABSENT": 1,
    "VERIFY_RECORD_PRESENT": 2,
    "VERIFY_RECORD_REDACTED": 3,
    "VERIFY_RECORD_ANONYMIZED": 4,
    "VERIFY_DATA_FLOW_DISABLED": 5,
    "VERIFY_RESTORE_BLOCKED": 6,
}

STEP_REQUIRED_KEYS = [
    "step_no", "phase", "system_id", "resource_id",
    "operation", "state", "evidence_id",
]


def parse_utc(ts: Optional[str]) -> Optional[datetime]:
    if ts is None or not isinstance(ts, str) or not ts.strip():
        return None
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(timezone.utc)


def normalize_email(email: Optional[str]) -> str:
    if email is None or not isinstance(email, str):
        return ""
    e = email.strip()
    e = unicodedata.normalize("NFC", e)
    e = e.lower()
    if "@" in e:
        local, domain = e.rsplit("@", 1)
        local = local.split("+", 1)[0]
        local = re.sub(r"\s+", "", local)
        e = local + "@" + domain
    else:
        e = re.sub(r"\s+", "", e)
    return e


def normalize_phone(phone: Optional[str]) -> str:
    if phone is None or not isinstance(phone, str):
        return ""
    return re.sub(r"\D", "", phone)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_csv(path: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    try:
        with open(path, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append({k: (v if v is not None else "") for k, v in row.items()})
    except FileNotFoundError:
        return []
    except UnicodeDecodeError:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append({k: (v if v is not None else "") for k, v in row.items()})
    return rows


def write_jsonl_trace(path: str, records: List[Dict[str, Any]]) -> None:
    with open(path, "a", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")


def safe_get(d: Dict[str, Any], key: str, default: Any = None) -> Any:
    v = d.get(key, default)
    return v if v is not None else default


def step_key(step: Dict[str, Any]) -> Tuple[int, int, str, str]:
    op = step.get("operation", "")
    prec = OPERATION_PRECEDENCE.get(op, 999)
    sys_id = step.get("system_id", "")
    res_id = step.get("resource_id", "")
    return (prec, sys_id, res_id)


def validate_step_keys(step: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    keys = set(step.keys())
    required = set(STEP_REQUIRED_KEYS)
    missing = required - keys
    extra = keys - required
    if missing:
        errors.append(f"missing keys: {sorted(missing)}")
    if extra:
        errors.append(f"extra keys: {sorted(extra)}")
    return errors


def validate_operation_state(operation: str, state: str) -> List[str]:
    errors: List[str] = []
    allowed_states = ALLOWED_OPERATION_STATES.get(operation, [])
    if state not in allowed_states:
        errors.append(f"state '{state}' not allowed for operation '{operation}' (allowed: {allowed_states})")
    return errors


def redact_for_log(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "[REDACTED]"
    return value[:2] + "***" + value[-2:]


def atomic_write_text(path: str, content: str, encoding: str = "utf-8") -> None:
    """Write text atomically: temp file in same dir, fsync, os.replace."""
    import os, tempfile
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp_", dir=d)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass

