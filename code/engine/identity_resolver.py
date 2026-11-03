"""
IdentityResolver — Temporal Identity Graph.
"""
import re
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set
from .common import parse_utc, normalize_email, normalize_phone, sha256_hex, load_csv, redact_for_log


class IdentityResult:
    def __init__(self, status, user_ids, search_keys, identifier_details, reasoning):
        self.status = status
        self.user_ids = user_ids
        self.search_keys = search_keys
        self.identifier_details = identifier_details
        self.reasoning = reasoning


class IdentityResolver:
    def __init__(self, identities_path, audit_log_path):
        self.identities_path = identities_path
        self.audit_log_path = audit_log_path
        self.identity_graph = {}
        self._email_to_users = {}
        self._phone_to_users = {}
        self._hash_to_users = {}
        self._loaded = False

    def load(self):
        if self._loaded:
            return
        identities = load_csv(self.identities_path)
        audit_log = load_csv(self.audit_log_path)

        user_current = {}
        for row in identities:
            uid = row.get("user_id", "")
            if not uid:
                continue
            user_current[uid] = {
                "name": row.get("name", ""),
                "email": row.get("email", ""),
                "phone": row.get("phone", ""),
                "email_hash": row.get("email_hash", ""),
                "updated_at": row.get("updated_at", ""),
            }

        changes = {}
        for row in audit_log:
            uid = row.get("user_id", "")
            field = row.get("field_name", "")
            if not uid or not field:
                continue
            key = f"{uid}|{field}"
            changes.setdefault(key, []).append({
                "audit_id": row.get("audit_id", ""),
                "event_time": parse_utc(row.get("event_time", "")),
                "old_value": row.get("old_value", ""),
                "new_value": row.get("new_value", ""),
            })

        for key in changes:
            changes[key].sort(key=lambda c: (c["event_time"] is None, c["event_time"] or datetime.min.replace(tzinfo=timezone.utc)))

        for uid, cur in user_current.items():
            graph_entry = {
                "user_id": uid,
                "name": cur["name"],
                "identifiers": {"email": [], "phone": [], "email_hash": []},
                "all_search_keys": set(),
            }

            for field in ["email", "phone", "email_hash"]:
                current_value = cur[field]
                current_updated = parse_utc(cur["updated_at"])
                change_list = changes.get(f"{uid}|{field}", [])

                if change_list:
                    first_change = change_list[0]
                    if first_change["old_value"]:
                        graph_entry["identifiers"][field].append({
                            "value": first_change["old_value"],
                            "valid_from": None,
                            "valid_to": first_change["event_time"],
                        })
                    for i in range(len(change_list)):
                        ch = change_list[i]
                        if ch["new_value"]:
                            next_time = change_list[i + 1]["event_time"] if i + 1 < len(change_list) else None
                            graph_entry["identifiers"][field].append({
                                "value": ch["new_value"],
                                "valid_from": ch["event_time"],
                                "valid_to": next_time,
                            })
                else:
                    graph_entry["identifiers"][field].append({
                        "value": current_value,
                        "valid_from": current_updated,
                        "valid_to": None,
                    })

                for ident in graph_entry["identifiers"][field]:
                    val = ident["value"]
                    if not val:
                        continue
                    if field == "email":
                        norm = normalize_email(val)
                    elif field == "phone":
                        norm = normalize_phone(val)
                    else:
                        norm = val
                    if norm:
                        graph_entry["all_search_keys"].add(norm)
                    if norm:
                        graph_entry["all_search_keys"].add(sha256_hex(norm))
                    graph_entry["all_search_keys"].add(val)

            self.identity_graph[uid] = graph_entry

            for ident in graph_entry["identifiers"]["email"]:
                val = normalize_email(ident["value"])
                if val:
                    self._email_to_users.setdefault(val, set()).add(uid)
                    self._email_to_users.setdefault(sha256_hex(val), set()).add(uid)
            for ident in graph_entry["identifiers"]["phone"]:
                val = normalize_phone(ident["value"])
                if val:
                    self._phone_to_users.setdefault(val, set()).add(uid)
            for ident in graph_entry["identifiers"]["email_hash"]:
                val = ident["value"]
                if val:
                    self._hash_to_users.setdefault(val, set()).add(uid)

        self._loaded = True

    def _identifier_valid_at(self, idents, check_time):
        valid = []
        if check_time is None:
            return valid
        for ident in idents:
            vf = ident["valid_from"]
            vt = ident["valid_to"]
            val = ident["value"]
            if not val:
                continue
            from_ok = (vf is None) or (vf <= check_time)
            to_ok = (vt is None) or (check_time < vt)
            if from_ok and to_ok:
                valid.append(val)
        return valid

    def resolve(self, request_email, requested_at, audit_at):
        reasoning = []
        norm_email = normalize_email(request_email)
        email_hash = sha256_hex(norm_email) if norm_email else ""

        req_time = parse_utc(requested_at)
        audit_time = parse_utc(audit_at)

        matching_users = set()
        match_details = {}

        for key in [norm_email, email_hash]:
            if not key:
                continue
            users = self._email_to_users.get(key, set())
            for uid in users:
                matching_users.add(uid)
                match_details.setdefault(uid, []).append(f"email={redact_for_log(key)}")

        if not matching_users:
            norm_phone = normalize_phone(request_email)
            if norm_phone:
                users = self._phone_to_users.get(norm_phone, set())
                for uid in users:
                    matching_users.add(uid)
                    match_details.setdefault(uid, []).append(f"phone={redact_for_log(norm_phone)}")

        if not matching_users:
            reasoning.append(f"No user_id found for request email {redact_for_log(request_email)}")
            return IdentityResult(
                status="UNRESOLVED",
                user_ids=[],
                search_keys=set(),
                identifier_details={},
                reasoning=reasoning,
            )

        if len(matching_users) > 1:
            reasoning.append(
                f"Ambiguous: email {redact_for_log(request_email)} matches {len(matching_users)} users: "
                + ", ".join(sorted(matching_users))
            )
            return IdentityResult(
                status="AMBIGUOUS",
                user_ids=sorted(matching_users),
                search_keys=set(),
                identifier_details={"match_details": match_details},
                reasoning=reasoning,
            )

        uid = next(iter(matching_users))
        graph_entry = self.identity_graph[uid]

        all_keys = set()
        identifier_details = {"user_id": uid, "identifiers": {}}

        for field in ["email", "phone", "email_hash"]:
            idents = graph_entry["identifiers"][field]
            valid_values = self._identifier_valid_at(idents, audit_time) if audit_time else []
            all_values = [i["value"] for i in idents if i["value"]]
            identifier_details["identifiers"][field] = {
                "valid_at_audit": valid_values,
                "all_historical": all_values,
            }

            for val in all_values:
                if not val:
                    continue
                if field == "email":
                    norm = normalize_email(val)
                elif field == "phone":
                    norm = normalize_phone(val)
                else:
                    norm = val
                if norm:
                    all_keys.add(norm)
                    all_keys.add(sha256_hex(norm))
                all_keys.add(val)

        all_keys.add(uid)
        reasoning.append(f"Resolved to user_id={uid} using {len(all_keys)} search keys")
        return IdentityResult(
            status="RESOLVED",
            user_ids=[uid],
            search_keys=all_keys,
            identifier_details=identifier_details,
            reasoning=reasoning,
        )