"""
StateReconstructor — As-Of State Reconstruction.
"""
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import re
from .common import parse_utc, redact_for_log


class ResourceState:
    def __init__(self, system_id, resource_id, state, evidence_ids,
                 captured_at, data_category, record_data, is_unknown=False):
        self.system_id = system_id
        self.resource_id = resource_id
        self.state = state
        self.evidence_ids = evidence_ids
        self.captured_at = captured_at
        self.data_category = data_category
        self.record_data = record_data
        self.is_unknown = is_unknown


class StateReconstructor:
    def __init__(self, evidence_index):
        self.evidence_index = evidence_index

    def reconstruct_all(self, audit_at, search_keys, req_window=None, activities=None):
        results = {}
        audit_dt = parse_utc(audit_at)
        relevant = self.evidence_index.get_records_before(audit_dt)
        matched = []
        user_ids = {k for k in search_keys if k.startswith("user_")}
        for rec in relevant:
            if self._has_conflicting_owner(rec, search_keys):
                continue
            if self._matches_search_keys(rec, search_keys):
                matched.append(rec)
        # Second pass: include log/replica records sharing resource_id or trace_id with matched records
        matched_keys = set()
        for rec in matched:
            if rec.resource_id.startswith(("email:", "subj:", "match:", "corr:", "trace:")) or rec.resource_id == "unknown":
                continue
            matched_keys.add(rec.resource_id)
            if isinstance(rec.record_data, dict):
                line = rec.record_data.get("line", "")
                m = re.search(r'trace_id=(\S+)', line)
                if m:
                    matched_keys.add(f"trace:{m.group(1)}")
        for rec in relevant:
            if rec in matched:
                continue
            if self._has_conflicting_owner(rec, search_keys):
                continue
            if rec.resource_id in matched_keys:
                matched.append(rec)
                continue
            if isinstance(rec.record_data, dict):
                line = rec.record_data.get("line", "")
                m = re.search(r'trace_id=(\S+)', line)
                if m and f"trace:{m.group(1)}" in matched_keys:
                    matched.append(rec)
                    continue

        # Candidate resources loop removed per Task 8 to prevent speculative decoy resources
        pass

        PREFIX_MAP = {
            "account_": ("account_service", "USER_PROFILE"),
            "search_": ("search_service", "SEARCH_INDEX_ENTRY"),
            "analytics_": ("analytics_platform", "ANALYTICS_PROFILE"),
            "support_": ("support_platform", "SUPPORT_MESSAGE"),
            "export_": ("export_service", "USER_EXPORT"),
            "data_flow_": ("integration_service", "MARKETING_PROFILE"),
            "backup_": ("backup_service", "BACKUP_ARCHIVE"),
            "audit_record_": ("security_service", "SECURITY_AUDIT_LOG"),
            "tombstone_": ("identity_service", "ACCOUNT_TOMBSTONE"),
            "legal_hold_": ("legal_retention_service", "LEGAL_HOLD_RECORD"),
        }

        by_resource = {}
        for rec in matched:
            if rec.resource_id.startswith(("email:", "subj:", "match:", "corr:", "trace:")):
                continue
            if rec.resource_id == "unknown":
                continue
            sys_id = rec.system_id
            cat = rec.data_category
            for pfx, (def_sys, def_cat) in PREFIX_MAP.items():
                if rec.resource_id.startswith(pfx):
                    if sys_id in ("unknown", "document", "text") or not sys_id:
                        sys_id = def_sys
                    if cat in ("UNKNOWN", "LOG_ENTRY") or not cat:
                        cat = def_cat
                    break
            key = f"{sys_id}|{rec.resource_id}"
            by_resource.setdefault(key, []).append((rec, sys_id, cat))

        for key, rec_tuples in by_resource.items():
            recs = [t[0] for t in rec_tuples]
            sys_id = rec_tuples[0][1]
            cat = rec_tuples[0][2]

            def _rec_priority(r):
                txt = r.raw_text or ""
                has_status = 1 if ("http_status" in txt or "rows=" in txt or "completed" in txt) else 0
                ca = r.captured_at or datetime.min.replace(tzinfo=timezone.utc)
                return (has_status, ca)
            recs.sort(key=_rec_priority, reverse=True)
            newest = recs[0]
            newest.data_category = cat
            newest.system_id = sys_id
            state = self._derive_state(newest)
            results[key] = ResourceState(
                system_id=sys_id,
                resource_id=newest.resource_id,
                state=state,
                evidence_ids=[r.file_id for r in recs],
                captured_at=newest.captured_at,
                data_category=cat,
                record_data=newest.record_data,
                is_unknown=(state == "UNKNOWN"),
            )
        return results

    def _matches_search_keys(self, rec, search_keys):
        from .common import normalize_email, sha256_hex, normalize_phone
        record_data = rec.record_data if isinstance(rec.record_data, dict) else {}

        def _check_val(val):
            if not val:
                return False
            if isinstance(val, str):
                if val in search_keys:
                    return True
                norm = normalize_email(val)
                if norm and (norm in search_keys or sha256_hex(norm) in search_keys):
                    return True
                np_ = normalize_phone(val)
                if np_ and np_ in search_keys:
                    return True
            elif isinstance(val, dict):
                return any(_check_val(v) for v in val.values())
            elif isinstance(val, (list, tuple, set)):
                return any(_check_val(v) for v in val)
            return False

        if _check_val(record_data):
            return True
        for field in ["email", "requester_email", "owner_email", "customer_email",
                      "match_key", "correlation_key", "subject_key",
                      "user_id", "customer_reference", "subject_reference"]:
            val = record_data.get(field, "")
            if val and isinstance(val, str):
                from .common import normalize_email, sha256_hex, normalize_phone
                if val in search_keys:
                    return True
                norm = normalize_email(val)
                if norm and norm in search_keys:
                    return True
                h = sha256_hex(norm) if norm else ""
                if h and h in search_keys:
                    return True
                np_ = normalize_phone(val)
                if np_ and np_ in search_keys:
                    return True
        phone = record_data.get("phone", "") or record_data.get("requester_phone", "") or record_data.get("owner_phone", "")
        if phone:
            from .common import normalize_phone
            norm_phone = normalize_phone(phone)
            if norm_phone and norm_phone in search_keys:
                return True
        if rec.resource_id and rec.resource_id in search_keys:
            return True
        emails = record_data.get("emails", [])
        if isinstance(emails, list):
            from .common import normalize_email, sha256_hex
            for email in emails:
                norm = normalize_email(email)
                if norm and norm in search_keys:
                    return True
                h = sha256_hex(norm) if norm else ""
                if h and h in search_keys:
                    return True
        raw_text = rec.raw_text or ""
        if raw_text:
            import re
            found_emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', raw_text)
            from .common import normalize_email, sha256_hex
            for email in found_emails:
                norm = normalize_email(email)
                if norm and norm in search_keys:
                    return True
                h = sha256_hex(norm) if norm else ""
                if h and h in search_keys:
                    return True
            for key_name in ["lookup_key", "subject_reference", "customer_reference",
                             "user_id", "customer_email", "requester_email", "owner_email"]:
                m = re.search(rf'{key_name}=(\S+)', raw_text)
                if m:
                    val = m.group(1)
                    if val in search_keys:
                        return True
                    norm = normalize_email(val)
                    if norm and norm in search_keys:
                        return True
                    from .common import normalize_phone
                    np_ = normalize_phone(val)
                    if np_ and np_ in search_keys:
                        return True
        return False

    def _derive_state(self, rec):
        record_data = rec.record_data if isinstance(rec.record_data, dict) else {}
        data_category = rec.data_category
        system_id = rec.system_id

        # 1. Explicit pre-extracted state takes precedence
        if "state" in record_data and record_data["state"] in ("ABSENT", "PRESENT", "ANONYMIZED", "REDACTED", "BLOCKED", "DISABLED", "ACTIVE"):
            return record_data["state"]

        # Log entries: parse status from line
        line = record_data.get("line", "") if isinstance(record_data, dict) else ""
        if rec.data_category == "LOG_ENTRY" or (isinstance(line, str) and line):
            if "http_status=404" in line or "rows=0" in line:
                return "ABSENT"
            if "http_status=200" in line:
                return "PRESENT"
            if "enabled=true" in line.lower() or "enabled=1" in line.lower():
                return "ACTIVE"
            if "enabled=false" in line.lower() or "enabled=0" in line.lower():
                return "DISABLED"
            if "restore_allowed=true" in line.lower() or "restore_allowed=1" in line.lower():
                return "PRESENT"
            if "restore_allowed=false" in line.lower() or "restore_allowed=0" in line.lower():
                return "BLOCKED"
            m = None
            import re
            m = re.search(r'rows=(\d+)', line)
            if m:
                try:
                    if int(m.group(1)) == 0:
                        return "ABSENT"
                    return "PRESENT"
                except ValueError:
                    pass
            return "PRESENT"
        status_code = record_data.get("status_code", None) if isinstance(record_data, dict) else None
        if status_code is not None:
            try:
                sc = int(status_code)
                if sc == 404:
                    return "ABSENT"
            except (ValueError, TypeError):
                pass
        if isinstance(record_data, dict):
            if "state" in record_data and record_data["state"] in ("ABSENT", "PRESENT", "ANONYMIZED", "REDACTED", "BLOCKED", "DISABLED", "ACTIVE"):
                return record_data["state"]
            if "profile" in record_data and record_data.get("profile") is None:
                return "ABSENT"
            if record_data.get("rows") == 0:
                return "ABSENT"
            if record_data.get("action") in ("DELETE_RECORD", "deleted", "remove"):
                return "ABSENT"
            if record_data.get("marker_found") is False:
                return "PRESENT"
            if record_data.get("download_available") is True:
                return "PRESENT"
            if record_data.get("restore_allowed") is not None:
                ra = record_data.get("restore_allowed")
                if ra is False or str(ra).lower() == "false" or ra == 0 or str(ra) == "0":
                    return "BLOCKED"
                return "PRESENT"
            if record_data.get("enabled") is not None:
                en = record_data.get("enabled")
                if en is False or str(en).lower() == "false" or en == 0 or str(en) == "0":
                    return "DISABLED"
                if record_data.get("last_delivery_status") == "stopped":
                    return "DISABLED"
                return "ACTIVE"
            if record_data.get("last_delivery_status") == "stopped":
                return "DISABLED"
            if record_data.get("audience_cohort") is not None:
                if not self._has_identifiers(record_data):
                    return "ANONYMIZED"
            if record_data.get("message_text") == "[REDACTED]":
                return "REDACTED"
            if "requester_email" in record_data and record_data.get("requester_email") is None and not record_data.get("requester_phone"):
                return "REDACTED"

        account_status = record_data.get("account_status", "") if isinstance(record_data, dict) else ""
        if account_status and str(account_status).upper() in ("DELETED", "DELETION_PENDING", "INACTIVE"):
            if self._has_identifiers(record_data):
                return "PRESENT"
            return "REDACTED"
        if self._has_identifiers(record_data):
            return "PRESENT"
        if data_category in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
            return "ANONYMIZED"
        if data_category == "ACCOUNT_TOMBSTONE":
            return "REDACTED"
        return "PRESENT"

    def _has_identifiers(self, record_data):
        identifier_fields = ["email", "phone", "full_name", "name", "email_hash", "requester_email", "owner_email", "customer_email"]
        for field in identifier_fields:
            val = record_data.get(field, None)
            if val and isinstance(val, str) and val.strip() and val.lower() not in ("null", "none", ""):
                if self._is_partially_redacted(val):
                    continue
                return True
        return False

    def _is_partially_redacted(self, val):
        import re
        if "@" in val:
            local, domain = val.split("@", 1)
            if "*" in local and len(local) > 2:
                visible = local.replace("*", "")
                if len(visible) > 2:
                    return False
                return True
        if "*" in val:
            digits = re.sub(r"\D", "", val)
            if len(digits) > 4:
                return False
            return True
        return False

    def _has_conflicting_owner(self, rec, search_keys):
        rd = rec.record_data if isinstance(rec.record_data, dict) else {}
        user_ids = {k for k in search_keys if k.startswith("user_")}
        for uid_field in ["customer_reference", "subject_reference", "user_id", "subject_selector", "subject_ref", "subject_key", "correlation_key"]:
            val = rd.get(uid_field)
            if val and isinstance(val, str) and val.startswith("user_"):
                if user_ids and val not in user_ids:
                    return True
        for em_field in ["email", "requester_email", "owner_email", "customer_email", "subject_reference", "subject_key", "lookup_key", "query"]:
            val = rd.get(em_field)
            if val and isinstance(val, str) and "@" in val:
                from .common import normalize_email, sha256_hex
                norm = normalize_email(val)
                if norm and norm not in search_keys and sha256_hex(norm) not in search_keys:
                    return True
        return False
