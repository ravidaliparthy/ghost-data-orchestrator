"""
EvidenceIndex — Per-format Evidence Extraction and Indexing.
"""
import json
import re
import sqlite3
import os
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from .common import (
    load_csv, parse_utc, normalize_email, normalize_phone, sha256_hex,
    redact_for_log,
)


class EvidenceRecord:
    def __init__(self, file_id, file_path, origin, captured_at,
                 data_category, system_id, resource_id, record_data,
                 extraction_quality="HIGH", raw_text=None):
        self.file_id = file_id
        self.file_path = file_path
        self.origin = origin
        self.captured_at = captured_at
        self.data_category = data_category
        self.system_id = system_id
        self.resource_id = resource_id
        self.record_data = record_data
        self.extraction_quality = extraction_quality
        self.raw_text = raw_text

class EvidenceIndex:
    def __init__(self, evidence_files_csv_path, evidence_root):
        self.evidence_files_csv_path = evidence_files_csv_path
        self.evidence_root = evidence_root
        self.manifest = []
        self.records = []
        self._by_email = {}
        self._by_phone = {}
        self._by_hash = {}
        self._by_user_id = {}
        self._by_resource = {}
        self._by_system_resource = {}
        self.missing_files = []
        self._loaded = False

    def _extract_sql(self, full_path, file_id, origin, captured_at):
        records = []
        try:
            conn = sqlite3.connect(":memory:")
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                sql_text = f.read()
            conn.executescript(sql_text)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cur.fetchall()]
            for table in tables:
                try:
                    cur.execute(f"SELECT * FROM {table}")
                    columns = [d[0] for d in cur.description]
                    rows = cur.fetchall()
                    for row in rows:
                        row_dict = dict(zip(columns, row))
                        resource_id = row_dict.get("resource_id", row_dict.get("id", "unknown"))
                        # Handle customer_data_* tables (JSON records)
                        if table.startswith("customer_data_"):
                            system_id = row_dict.get("origin_system", "unknown")
                            collection = row_dict.get("collection_name", "")
                            data_category = self._infer_category_from_collection(collection) if collection else self._infer_category_from_system(system_id)
                            # flatten record_json
                            rj = row_dict.get("record_json")
                            if isinstance(rj, str):
                                try:
                                    parsed = json.loads(rj)
                                    if isinstance(parsed, dict):
                                        merged = dict(row_dict)
                                        merged.update(parsed)
                                        row_dict = merged
                                        if not resource_id or resource_id == "unknown":
                                            resource_id = parsed.get("resource_id", parsed.get("id", "unknown"))
                                except Exception:
                                    pass
                        else:
                            system_id = self._infer_system_from_table(table)
                            data_category = self._infer_category_from_table(table)
                        records.append(EvidenceRecord(
                            file_id=file_id, file_path=full_path, origin=origin,
                            captured_at=captured_at, data_category=data_category,
                            system_id=system_id, resource_id=str(resource_id),
                            record_data=row_dict, extraction_quality="HIGH",
                        ))
                except Exception:
                    continue
            conn.close()
        except Exception as e:
            records.append(EvidenceRecord(
                file_id=file_id, file_path=full_path, origin=origin,
                captured_at=captured_at, data_category="UNKNOWN",
                system_id="unknown", resource_id="unknown",
                record_data={"error": f"SQL parse error: {str(e)[:200]}"},
                extraction_quality="ERROR",
            ))
        return records

    def load(self):
        if self._loaded:
            return
        self.manifest = load_csv(self.evidence_files_csv_path)
        for entry in self.manifest:
            file_id = entry.get("file_id", "")
            file_path = entry.get("file_path", "")
            origin = entry.get("origin", "")
            captured_at = parse_utc(entry.get("captured_at", ""))
            full_path = os.path.join(self.evidence_root, file_path)
            if not os.path.exists(full_path):
                self.missing_files.append(file_id)
                continue
            try:
                extracted = self._extract_file(full_path, file_id, origin, captured_at)
                for rec in extracted:
                    self.records.append(rec)
                    self._index_record(rec)
            except Exception as e:
                self.records.append(EvidenceRecord(
                    file_id=file_id, file_path=file_path, origin=origin,
                    captured_at=captured_at, data_category="UNKNOWN",
                    system_id="unknown", resource_id="unknown",
                    record_data={"error": str(e)[:200]},
                    extraction_quality="ERROR",
                ))
        self._loaded = True

    def _extract_file(self, full_path, file_id, origin, captured_at):
        ext = os.path.splitext(full_path)[1].lower()
        if ext == ".sql":
            return self._extract_sql(full_path, file_id, origin, captured_at)
        elif ext == ".json":
            return self._extract_json(full_path, file_id, origin, captured_at)
        elif ext == ".log":
            return self._extract_log(full_path, file_id, origin, captured_at)
        elif ext == ".pdf":
            return self._extract_pdf(full_path, file_id, origin, captured_at)
        elif ext in (".png", ".jpg", ".jpeg"):
            return self._extract_image(full_path, file_id, origin, captured_at)
        elif ext == ".txt":
            return self._extract_text(full_path, file_id, origin, captured_at)
        else:
            return [EvidenceRecord(
                file_id=file_id, file_path=full_path, origin=origin,
                captured_at=captured_at, data_category="UNKNOWN",
                system_id="unknown", resource_id="unknown",
                record_data={"note": f"Unsupported extension: {ext}"},
                extraction_quality="UNKNOWN",
            )]

    def _extract_json(self, full_path, file_id, origin, captured_at):
        records = []
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except Exception as e:
            return [EvidenceRecord(
                file_id=file_id, file_path=full_path, origin=origin,
                captured_at=captured_at, data_category="UNKNOWN",
                system_id="unknown", resource_id="unknown",
                record_data={"error": f"JSON parse error: {str(e)[:200]}"},
                extraction_quality="ERROR",
            )]
        records.extend(self._traverse_json(data, file_id, origin, captured_at, full_path))
        return records

    def _traverse_json(self, data, file_id, origin, captured_at, path):
        records = []
        if isinstance(data, dict):
            if "snapshots" in data:
                for snap in data.get("snapshots", []):
                    snap_captured = parse_utc(snap.get("captured_at", "")) or captured_at
                    ds = snap.get("data_store", "unknown")
                    collection = snap.get("collection", "unknown")
                    for rec in snap.get("records", []):
                        merged = dict(rec)
                        rid = merged.get("resource_id", "unknown")
                        records.append(EvidenceRecord(
                            file_id=file_id, file_path=path, origin=origin,
                            captured_at=snap_captured,
                            data_category=self._infer_category_from_collection(collection),
                            system_id=ds,
                            resource_id=str(rid),
                            record_data=merged, extraction_quality="HIGH",
                        ))
                return records
            elif "service_exports" in data:
                for svc_name, svc_data in data.get("service_exports", {}).items():
                    for key, items in svc_data.items():
                        if isinstance(items, list):
                            for item in items:
                                if isinstance(item, dict):
                                    merged = dict(item)
                                    prof = item.get("profile")
                                    if isinstance(prof, dict):
                                        merged.update(prof)
                                    rid = merged.get("resource_id", "unknown")
                                    records.append(EvidenceRecord(
                                        file_id=file_id, file_path=path, origin=origin,
                                        captured_at=captured_at,
                                        data_category=self._infer_category_from_system(svc_name),
                                        system_id=svc_name, resource_id=str(rid),
                                        record_data=merged, extraction_quality="HIGH",
                                    ))
                return records
            else:
                resource_id = data.get("resource_id", "unknown")
                system_id = data.get("data_store", data.get("source", "unknown"))
                records.append(EvidenceRecord(
                    file_id=file_id, file_path=path, origin=origin,
                    captured_at=captured_at,
                    data_category=self._infer_category_from_system(str(system_id)),
                    system_id=str(system_id), resource_id=str(resource_id),
                    record_data=data, extraction_quality="HIGH",
                ))
            for k, v in data.items():
                records.extend(self._traverse_json(v, file_id, origin, captured_at, f"{path}.{k}"))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                records.extend(self._traverse_json(item, file_id, origin, captured_at, f"{path}[{i}]"))
        return records

    def _extract_log(self, full_path, file_id, origin, captured_at):
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            return [EvidenceRecord(
                file_id=file_id, file_path=full_path, origin=origin,
                captured_at=captured_at, data_category="UNKNOWN",
                system_id="unknown", resource_id="unknown",
                record_data={"error": f"Log read error: {str(e)[:200]}"},
                extraction_quality="ERROR",
            )]

        records = []
        traces = {}
        standalone = []

        for line in lines:
            line_clean = line.strip()
            if not line_clean:
                continue

            parsed_fields = {}
            idx = line_clean.find('{')
            if idx != -1:
                try:
                    parsed_fields = json.loads(line_clean[idx:])
                except Exception:
                    pass

            if not parsed_fields:
                if ' | ' in line_clean:
                    parts = [p.strip() for p in line_clean.split(' | ')]
                    if len(parts) >= 5:
                        parsed_fields["timestamp"] = parts[0]
                        parsed_fields["level"] = parts[1]
                        parsed_fields["service"] = parts[2]
                        parsed_fields["trace_id"] = parts[3]
                        parsed_fields["event"] = parts[4]
                        rest = " | ".join(parts[5:]) if len(parts) > 5 else ""
                        for m in re.finditer(r'(\b[a-zA-Z_][a-zA-Z0-9_]*)=(?:"([^"]*)"|(\S+))', rest):
                            k = m.group(1)
                            v = m.group(2) if m.group(2) is not None else m.group(3)
                            if v.lower() in ("null", "none"):
                                parsed_fields[k] = None
                            elif v.isdigit():
                                parsed_fields[k] = int(v)
                            else:
                                parsed_fields[k] = v

            if not parsed_fields:
                line_unescaped = line_clean.replace('\\"', '"')
                for m in re.finditer(r'(\b[a-zA-Z_][a-zA-Z0-9_]*)=(?:"([^"]*)"|(\S+))', line_unescaped):
                    k = m.group(1)
                    v = m.group(2) if m.group(2) is not None else m.group(3)
                    if k == 'message':
                        for m2 in re.finditer(r'(\b[a-zA-Z_][a-zA-Z0-9_]*)=(?:"([^"]*)"|(\S+))', v):
                            k2 = m2.group(1)
                            v2 = m2.group(2) if m2.group(2) is not None else m2.group(3)
                            if v2.lower() in ("null", "none"):
                                parsed_fields[k2] = None
                            elif v2.isdigit():
                                parsed_fields[k2] = int(v2)
                            else:
                                parsed_fields[k2] = v2
                    else:
                        if v.lower() in ("null", "none"):
                            parsed_fields[k] = None
                        elif v.isdigit():
                            parsed_fields[k] = int(v)
                        else:
                            parsed_fields[k] = v

            parsed_fields["line"] = line_clean[:500]
            sys_id = parsed_fields.get("service") or parsed_fields.get("function") or parsed_fields.get("logger") or "unknown"
            parsed_fields["system"] = sys_id

            trace_id = parsed_fields.get("trace_id")
            if not trace_id:
                req_id = parsed_fields.get("requestId")
                if req_id and isinstance(req_id, str) and req_id.startswith("tr-"):
                    trace_id = req_id
                    parsed_fields["trace_id"] = trace_id
            if trace_id:
                traces.setdefault(trace_id, []).append(parsed_fields)
            else:
                standalone.append(parsed_fields)

        # Process grouped traces
        for tid, items in traces.items():
            user_keys = set()
            trace_rids = set()
            for it in items:
                for k in ["lookup_key", "subject_key", "correlation_key", "subject_ref", "user_id", "email", "customer_reference", "subject_reference"]:
                    val = it.get(k)
                    if val and str(val).lower() not in ("null", "none"):
                        user_keys.add(str(val))
                rid = it.get("resource_id")
                if rid and not str(rid).startswith(("email:", "subj:", "unknown", "corr:", "match:")):
                    trace_rids.add(str(rid))

            for it in items:
                if user_keys:
                    it["correlated_user_keys"] = list(user_keys)
                    for uk in user_keys:
                        if "@" in uk:
                            it.setdefault("email", uk)
                        elif uk.startswith("user_"):
                            it.setdefault("user_id", uk)
                            it.setdefault("customer_reference", uk)
                rid = it.get("resource_id")
                if not rid and trace_rids:
                    rid = next(iter(trace_rids))
                    it["resource_id"] = rid

                if rid and not str(rid).startswith(("email:", "subj:", "unknown", "corr:", "match:")):
                    cur_sys = it.get("system", "unknown")
                    records.append(EvidenceRecord(
                        file_id=file_id, file_path=full_path, origin=origin,
                        captured_at=captured_at, data_category=self._infer_category_from_system(cur_sys),
                        system_id=cur_sys, resource_id=str(rid),
                        record_data=it, extraction_quality="HIGH",
                        raw_text=it.get("line", ""),
                    ))

        # Process standalone lines
        for it in standalone:
            rid = it.get("resource_id")
            if rid and not str(rid).startswith(("email:", "subj:", "unknown", "corr:", "match:")):
                cur_sys = it.get("system", "unknown")
                records.append(EvidenceRecord(
                    file_id=file_id, file_path=full_path, origin=origin,
                    captured_at=captured_at, data_category=self._infer_category_from_system(cur_sys),
                    system_id=cur_sys, resource_id=str(rid),
                    record_data=it, extraction_quality="MEDIUM",
                    raw_text=it.get("line", ""),
                ))

        return records

    def _extract_pdf(self, full_path, file_id, origin, captured_at):
        text = ""
        quality = "LOW"
        try:
            from .pdf_extractor import extract_pdf_text as _extract_pdf_text
            text = _extract_pdf_text(full_path)
            if text and len(text) > 20:
                quality = "HIGH"
            else:
                raise RuntimeError("empty pdf text")
        except Exception:
            try:
                with open(full_path, "rb") as f:
                    raw = f.read()
                text = re.findall(rb'[\x20-\x7e]{4,}', raw)
                text = b" ".join(text).decode("utf-8", errors="replace")
                quality = "RAW_SCAN"
            except Exception:
                text = ""
                quality = "ERROR"

        emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', text)
        phones = re.findall(r'\+?[0-9]{1,4}[\s\-]?[0-9]{2,4}[\s\-]?[0-9]{3,4}[\s\-]?[0-9]{3,5}', text)
        user_ids = re.findall(r'\buser_[0-9]+\b', text)
        resource_ids = re.findall(r'\b(account_[0-9]+|search_[0-9]+|analytics_[0-9]+|backup_[0-9]+|support_[0-9]+|tombstone_[0-9]+|data_flow_[0-9]+|audit_record_[0-9]+|legal_hold_[0-9]+)\b', text)

        records = []
        if resource_ids:
            for rid in set(resource_ids):
                sys_id = "support_platform" if rid.startswith("support_") else (
                    "security_service" if rid.startswith("audit_record_") else (
                        "account_service" if rid.startswith("account_") else "unknown"
                    )
                )
                cat = "SUPPORT_MESSAGE" if rid.startswith("support_") else (
                    "SECURITY_AUDIT_LOG" if rid.startswith("audit_record_") else "USER_PROFILE"
                )
                rec_data = {
                    "resource_id": rid,
                    "system_id": sys_id,
                    "emails": emails,
                    "phones": phones,
                    "user_ids": user_ids,
                    "text_excerpt": text[:1000]
                }
                if emails: rec_data["email"] = emails[0]
                if phones: rec_data["phone"] = phones[0]
                if user_ids: rec_data["user_id"] = user_ids[0]
                records.append(EvidenceRecord(
                    file_id=file_id, file_path=full_path, origin=origin,
                    captured_at=captured_at, data_category=cat,
                    system_id=sys_id, resource_id=rid,
                    record_data=rec_data, extraction_quality=quality,
                    raw_text=text[:1000]
                ))
        elif user_ids or emails:
            rec_data = {
                "resource_id": f"doc_{file_id}",
                "emails": emails,
                "phones": phones,
                "user_ids": user_ids,
                "text_excerpt": text[:1000]
            }
            if emails: rec_data["email"] = emails[0]
            if user_ids: rec_data["user_id"] = user_ids[0]
            records.append(EvidenceRecord(
                file_id=file_id, file_path=full_path, origin=origin,
                captured_at=captured_at, data_category="SUPPORT_MESSAGE",
                system_id="support_platform", resource_id=f"doc_{file_id}",
                record_data=rec_data, extraction_quality=quality,
                raw_text=text[:1000]
            ))
        else:
            records.append(EvidenceRecord(
                file_id=file_id, file_path=full_path, origin=origin,
                captured_at=captured_at, data_category="DOCUMENT",
                system_id="document", resource_id="pdf_" + file_id,
                record_data={"text_excerpt": text[:1000], "emails": emails, "resource_ids": resource_ids},
                extraction_quality=quality,
                raw_text=text[:2000] if text else None,
            ))
        return records

    def _extract_image(self, full_path, file_id, origin, captured_at):
        return [EvidenceRecord(
            file_id=file_id, file_path=full_path, origin=origin,
            captured_at=captured_at, data_category="IMAGE",
            system_id="image", resource_id="img_" + file_id,
            record_data={"note": "OCR not available — image evidence unverified"},
            extraction_quality="UNVERIFIED",
        )]

    def _extract_text(self, full_path, file_id, origin, captured_at):
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except Exception as e:
            return [EvidenceRecord(
                file_id=file_id, file_path=full_path, origin=origin,
                captured_at=captured_at, data_category="UNKNOWN",
                system_id="unknown", resource_id="unknown",
                record_data={"error": f"Text read error: {str(e)[:200]}"},
                extraction_quality="ERROR",
            )]

        records = []
        lines = text.splitlines()
        has_table_rows = False
        for line in lines:
            line = line.strip()
            if not line or not line.startswith("-"):
                continue
            parts = [p.strip() for p in line.lstrip("-").split("|")]
            if len(parts) >= 6:
                has_table_rows = True
                ts, sys_id, res_id, cat, result, subj = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
                rec_data = {
                    "timestamp": ts,
                    "system_id": sys_id,
                    "resource_id": res_id,
                    "category": cat,
                    "result": result,
                    "subject": subj,
                    "line": line
                }
                if "@" in subj:
                    rec_data["email"] = subj
                elif subj.startswith("user_"):
                    rec_data["user_id"] = subj
                    rec_data["customer_reference"] = subj
                
                state = "PRESENT"
                if result in ("NOT_FOUND", "ABSENT", "DELETED"):
                    state = "ABSENT"
                elif result in ("ANONYMIZED",):
                    state = "ANONYMIZED"
                elif result in ("REDACTED",):
                    state = "REDACTED"
                elif result in ("BLOCKED",):
                    state = "BLOCKED"
                elif result in ("DISABLED",):
                    state = "DISABLED"
                elif result in ("ACTIVE",):
                    state = "ACTIVE"
                elif result in ("IDENTIFIABLE",):
                    state = "PRESENT"
                    rec_data["exposed_pii"] = True
                
                rec_data["state"] = state
                records.append(EvidenceRecord(
                    file_id=file_id, file_path=full_path, origin=origin,
                    captured_at=captured_at, data_category=cat,
                    system_id=sys_id, resource_id=res_id,
                    record_data=rec_data, extraction_quality="HIGH",
                    raw_text=line
                ))

        if not has_table_rows:
            emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', text)
            resource_ids = re.findall(r'(account_[0-9]+|search_[0-9]+|analytics_[0-9]+|backup_[0-9]+|support_[0-9]+|tombstone_[0-9]+|data_flow_[0-9]+|audit_record_[0-9]+|legal_hold_[0-9]+)', text)
            records.append(EvidenceRecord(
                file_id=file_id, file_path=full_path, origin=origin,
                captured_at=captured_at, data_category="TEXT_RECORD",
                system_id="text", resource_id="txt_" + file_id,
                record_data={"text_excerpt": text[:1000], "emails": emails, "resource_ids": resource_ids},
                extraction_quality="HIGH",
                raw_text=text[:2000] if text else None,
            ))
        return records

    def _infer_system_from_table(self, table):
        t = table.lower()
        if "customer_profiles" in t or "customer_accounts" in t:
            return "account_service"
        if "customer_search" in t or "search_documents" in t:
            return "search_service"
        if "customer_analytics" in t:
            return "analytics_platform"
        if "support_records" in t or "support_conversations" in t:
            return "support_platform"
        if "customer_exports" in t:
            return "export_service"
        if "connector_subscriptions" in t:
            return "integration_service"
        if "backup_restore" in t:
            return "backup_service"
        if "security_audit" in t:
            return "security_service"
        mapping = {
            "customer_profiles": "account_service",
        }
        return mapping.get(table, "unknown")

    def _infer_category_from_table(self, table):
        t = table.lower()
        if "customer_profiles" in t or "customer_accounts" in t:
            return "USER_PROFILE"
        if "customer_search" in t or "search_documents" in t:
            return "SEARCH_INDEX_ENTRY"
        if "customer_analytics" in t:
            return "ANALYTICS_PROFILE"
        if "support_records" in t or "support_conversations" in t:
            return "SUPPORT_MESSAGE"
        if "customer_exports" in t:
            return "USER_EXPORT"
        if "connector_subscriptions" in t:
            return "MARKETING_PROFILE"
        if "backup_restore" in t:
            return "BACKUP_ARCHIVE"
        if "security_audit" in t:
            return "SECURITY_AUDIT_LOG"
        return "UNKNOWN"

    def _infer_category_from_collection(self, collection):
        mapping = {
            "customer_profiles": "USER_PROFILE",
            "customer_search_documents": "SEARCH_INDEX_ENTRY",
            "customer_analytics_reports": "ANALYTICS_PROFILE",
            "support_conversations": "SUPPORT_MESSAGE",
            "security_events": "SECURITY_AUDIT_LOG",
            "deleted_customer_references": "ACCOUNT_TOMBSTONE",
        }
        return mapping.get(collection, "UNKNOWN")

    def _infer_category_from_system(self, system_id):
        mapping = {
            "account_service": "USER_PROFILE",
            "search_service": "SEARCH_INDEX_ENTRY",
            "analytics_platform": "ANALYTICS_PROFILE",
            "support_platform": "SUPPORT_MESSAGE",
            "export_service": "USER_EXPORT",
            "integration_service": "MARKETING_PROFILE",
            "backup_service": "BACKUP_ARCHIVE",
            "security_service": "SECURITY_AUDIT_LOG",
            "identity_service": "ACCOUNT_TOMBSTONE",
        }
        return mapping.get(system_id, "UNKNOWN")

    def _index_record(self, rec):
        record_data = rec.record_data if isinstance(rec.record_data, dict) else {}
        emails_found = list(record_data.get("emails", []))
        for field in ["email", "requester_email", "owner_email", "customer_email", "match_key", "correlation_key", "subject_key", "lookup_key"]:
            val = record_data.get(field, "")
            if val and isinstance(val, str) and "@" in val:
                emails_found.append(val)
        for uk in record_data.get("correlated_user_keys", []):
            if "@" in uk:
                emails_found.append(uk)
            elif uk.startswith("user_"):
                self._by_user_id.setdefault(uk, []).append(rec)
        for email in emails_found:
            norm = normalize_email(email)
            if norm:
                self._by_email.setdefault(norm, []).append(rec)
                self._by_hash.setdefault(sha256_hex(norm), []).append(rec)
        h = record_data.get("email_hash")
        if h and isinstance(h, str) and len(h) == 64:
            self._by_hash.setdefault(h.lower(), []).append(rec)
        phone = record_data.get("phone", "") or record_data.get("requester_phone", "") or record_data.get("owner_phone", "")
        if phone:
            norm_phone = normalize_phone(phone)
            if norm_phone:
                self._by_phone.setdefault(norm_phone, []).append(rec)
        for uid_field in ["user_id", "customer_reference", "subject_reference", "subject_selector", "subject_ref"]:
            uid_val = record_data.get(uid_field)
            if uid_val and isinstance(uid_val, str) and uid_val.startswith("user_"):
                self._by_user_id.setdefault(uid_val, []).append(rec)
        self._by_resource.setdefault(rec.resource_id, []).append(rec)
        self._by_system_resource.setdefault(f"{rec.system_id}|{rec.resource_id}", []).append(rec)

    def search_by_user_id(self, user_id):
        return self._by_user_id.get(user_id, [])

    def search_by_email(self, email):
        norm = normalize_email(email)
        results = list(self._by_email.get(norm, []))
        results += self._by_hash.get(sha256_hex(norm), [])
        return results

    def search_by_phone(self, phone):
        norm = normalize_phone(phone)
        return self._by_phone.get(norm, [])

    def search_by_resource(self, system_id, resource_id):
        return self._by_system_resource.get(f"{system_id}|{resource_id}", [])

    def search_by_resource_id(self, resource_id):
        return self._by_resource.get(resource_id, [])

    def get_records_before(self, audit_at):
        if audit_at is None:
            return []
        return [r for r in self.records if r.captured_at is not None and r.captured_at <= audit_at]
