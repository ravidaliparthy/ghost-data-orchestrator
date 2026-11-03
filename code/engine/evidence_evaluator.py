"""
EvidenceEvaluator
"""
from typing import List, Dict, Any, Optional, Tuple, Set
from datetime import datetime, timezone
from .common import (
    parse_utc, normalize_email, normalize_phone, sha256_hex,
    ALLOWED_OPERATION_STATES, VALID_STATUSES, redact_for_log, load_csv,
)


class Finding:
    def __init__(self, system_id, resource_id, operation, state, evidence_id, reasoning):
        self.system_id = system_id
        self.resource_id = resource_id
        self.operation = operation
        self.state = state
        self.evidence_id = evidence_id
        self.reasoning = reasoning


class Remediation:
    def __init__(self, system_id, resource_id, operation, state, reasoning):
        self.system_id = system_id
        self.resource_id = resource_id
        self.operation = operation
        self.state = state
        self.reasoning = reasoning


class Verification:
    def __init__(self, system_id, resource_id, operation, state, evidence_id, reasoning):
        self.system_id = system_id
        self.resource_id = resource_id
        self.operation = operation
        self.state = state
        self.evidence_id = evidence_id
        self.reasoning = reasoning


class CaseResult:
    def __init__(self, case_id, deletion_status, steps, contradictions,
                 reasonable_doubt, reasoning_trace, identity_result, intent_result):
        self.case_id = case_id
        self.deletion_status = deletion_status
        self.steps = steps
        self.contradictions = contradictions
        self.reasonable_doubt = reasonable_doubt
        self.reasoning_trace = reasoning_trace
        self.identity_result = identity_result
        self.intent_result = intent_result

class EvidenceEvaluator:
    def __init__(self, identity_resolver, intent_classifier, evidence_index,
                 state_reconstructor, resurrection_graph, rules_engine,
                 audit_evidence_index=None, system_activity_csv_path=None):
        self.identity_resolver = identity_resolver
        self.intent_classifier = intent_classifier
        self.evidence_index = evidence_index
        self.state_reconstructor = state_reconstructor
        self.resurrection_graph = resurrection_graph
        self.rules_engine = rules_engine
        self.audit_evidence_index = audit_evidence_index
        self.system_activity_csv_path = system_activity_csv_path

    def _manifest_captured(self, file_id):
        for entry in self.evidence_index.manifest:
            if entry.get("file_id") == file_id:
                try:
                    return parse_utc(entry.get("captured_at", ""))
                except Exception:
                    return None
        return None

    def _pick_evidence(self, ids, audit_dt):
        if not ids:
            return ""
        valid = []
        for eid in ids:
            cap = self._manifest_captured(eid)
            if cap is not None and cap <= audit_dt:
                valid.append((cap, eid))
        if valid:
            valid.sort(key=lambda x: x[0], reverse=True)
            return valid[0][1]
        for eid in ids:
            cap = self._manifest_captured(eid)
            if cap is None or (audit_dt is None or cap <= audit_dt):
                return eid
        return ""
    def evaluate_case(self, case):
        case_id = case.get("case_id", "unknown")
        email = case.get("email", "")
        requested_at = case.get("requested_at", "")
        reported_status = case.get("reported_status", "")
        reported_at = case.get("reported_at", "")
        audit_at = case.get("audit_at", "")
        request_text = case.get("request_text", "")

        reasoning_trace = []
        contradictions = 0

        intent = self.intent_classifier.classify(request_text)
        reasoning_trace.append({
            "step": "intent_classification",
            "result": "AUTHORIZED" if intent.authorized else "NOT_APPLICABLE",
            "confidence": intent.confidence,
            "reasons": intent.reasons,
            "language": intent.language,
        })

        if not intent.authorized:
            return CaseResult(
                case_id=case_id, deletion_status="NOT_APPLICABLE", steps=[],
                contradictions=0, reasonable_doubt=0.0,
                reasoning_trace=reasoning_trace,
                identity_result=None, intent_result=intent,
            )

        identity = self.identity_resolver.resolve(email, requested_at, audit_at)
        reasoning_trace.append({
            "step": "identity_resolution",
            "status": identity.status,
            "user_ids": identity.user_ids,
            "search_key_count": len(identity.search_keys),
            "reasoning": identity.reasoning,
        })

        if identity.status in ("UNRESOLVED", "AMBIGUOUS"):
            finding = Finding(
                system_id="identity_service", resource_id="unresolved_identity",
                operation="REPORT_REMAINING_RECORD", state="PRESENT", evidence_id="",
                reasoning=[f"Cannot resolve requester identity for email {redact_for_log(email)}"],
            )
            remediation = Remediation(
                system_id="identity_service", resource_id="unresolved_identity",
                operation="DELETE_RECORD", state="ABSENT",
                reasoning=["Resolve identity before processing deletion"],
            )
            verification = Verification(
                system_id="identity_service", resource_id="unresolved_identity",
                operation="VERIFY_RECORD_ABSENT", state="ABSENT", evidence_id="",
                reasoning=["Confirm identity resolved and record absent"],
            )
            steps = self._build_steps([finding], [remediation], [verification], "INCOMPLETE")
            return CaseResult(
                case_id=case_id, deletion_status="INCOMPLETE", steps=steps,
                contradictions=0, reasonable_doubt=1.0,
                reasoning_trace=reasoning_trace,
                identity_result=identity, intent_result=intent,
            )

        search_keys = identity.search_keys
        audit_dt = parse_utc(audit_at)
        all_evidence = self.evidence_index.get_records_before(audit_dt)
        matching_evidence = []
        for rec in all_evidence:
            if self._evidence_matches_user(rec, search_keys):
                matching_evidence.append(rec)
        reasoning_trace.append({
            "step": "evidence_gathering",
            "evidence_count": len(matching_evidence),
            "audit_at": audit_at,
            "boundary_rule": "captured_at <= audit_at (inclusive)",
        })

        activity_rows = self._load_activity_rows()
        req_window = (requested_at, reported_at)
        resource_states = self.state_reconstructor.reconstruct_all(
            audit_at, search_keys, req_window=req_window, activities=activity_rows
        )
        reasoning_trace.append({
            "step": "state_reconstruction",
            "resources_evaluated": len(resource_states),
            "unknown_states": sum(1 for s in resource_states.values() if s.is_unknown),
        })

        self.resurrection_graph.build(audit_at, activity_rows)
        reasoning_trace.append({
            "step": "resurrection_graph",
            "edges_total": len(self.resurrection_graph.edges),
            "active_edges": len(self.resurrection_graph.get_active_edges()),
        })

        findings = []
        remediations = []
        verifications = []
        retained_resources = []

        for key, state in resource_states.items():
            category = state.data_category
            if category == "UNKNOWN":
                continue
            context = self._build_rule_context(state, resource_states)
            required_action = self.rules_engine.required_action_for(category, context, audit_dt)
            if required_action is None:
                if category == "SUPPORT_MESSAGE":
                    required_action = "REDACT"
                elif category in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
                    required_action = "ANONYMIZE"
                elif category == "ACCOUNT_TOMBSTONE":
                    required_action = "REDACT"
                elif category == "EMAIL_DELIVERY_LOG":
                    required_action = "REDACT"
                elif category == "BACKUP_ARCHIVE":
                    required_action = "RETAIN"
                elif category == "SECURITY_AUDIT_LOG":
                    from .common import parse_utc as _pu
                    rt = _pu(state.record_data.get("retention_until")) if isinstance(state.record_data, dict) else None
                    if rt is not None and rt <= audit_dt:
                        required_action = "DELETE"
                    else:
                        required_action = "RETAIN"
                elif category == "LEGAL_HOLD_RECORD":
                    if context.get("legal_hold_active"):
                        required_action = "RETAIN"
                    else:
                        continue
                else:
                    continue
            if required_action == "DELETE":
                if state.state == "PRESENT":
                    ev_id = self._pick_evidence(state.evidence_ids, audit_dt)
                    if ev_id:
                        findings.append(Finding(
                            system_id=state.system_id, resource_id=state.resource_id,
                            operation="REPORT_REMAINING_RECORD", state="PRESENT",
                            evidence_id=ev_id,
                            reasoning=[f"{category} record {state.resource_id} still PRESENT at audit_at, rule requires DELETE"],
                        ))
                        remediations.append(Remediation(
                            system_id=state.system_id, resource_id=state.resource_id,
                            operation="DELETE_RECORD", state="ABSENT",
                            reasoning=["Delete record per rule"],
                        ))
                        verifications.append(Verification(
                            system_id=state.system_id, resource_id=state.resource_id,
                            operation="VERIFY_RECORD_ABSENT", state="ABSENT", evidence_id="",
                            reasoning=["Verify record deleted after remediation"],
                        ))
                elif state.state == "ABSENT":
                    verifications.append(Verification(
                        system_id=state.system_id, resource_id=state.resource_id,
                        operation="VERIFY_RECORD_ABSENT", state="ABSENT",
                        evidence_id=self._pick_evidence(state.evidence_ids, audit_dt),
                        reasoning=["Record confirmed absent per evidence"],
                    ))
                elif state.state == "UNKNOWN":
                    pass
            elif required_action == "REDACT":
                if state.state == "PRESENT":
                    ev_id = self._pick_evidence(state.evidence_ids, audit_dt)
                    if ev_id:
                        findings.append(Finding(
                            system_id=state.system_id, resource_id=state.resource_id,
                            operation="REPORT_EXPOSED_PII", state="PRESENT",
                            evidence_id=ev_id,
                            reasoning=[f"{category} record {state.resource_id} has exposed PII, rule requires REDACT"],
                        ))
                        remediations.append(Remediation(
                            system_id=state.system_id, resource_id=state.resource_id,
                            operation="REDACT_RECORD", state="REDACTED",
                            reasoning=["Redact prohibited identifiers per rule"],
                        ))
                        verifications.append(Verification(
                            system_id=state.system_id, resource_id=state.resource_id,
                            operation="VERIFY_RECORD_REDACTED", state="REDACTED", evidence_id="",
                            reasoning=["Verify identifiers redacted after remediation"],
                        ))
                elif state.state == "REDACTED":
                    verifications.append(Verification(
                        system_id=state.system_id, resource_id=state.resource_id,
                        operation="VERIFY_RECORD_REDACTED", state="REDACTED",
                        evidence_id=self._pick_evidence(state.evidence_ids, audit_dt),
                        reasoning=["Record confirmed redacted per evidence"],
                    ))
            elif required_action == "ANONYMIZE":
                if state.state == "PRESENT":
                    ev_id = self._pick_evidence(state.evidence_ids, audit_dt)
                    if ev_id:
                        findings.append(Finding(
                            system_id=state.system_id, resource_id=state.resource_id,
                            operation="REPORT_EXPOSED_PII", state="PRESENT",
                            evidence_id=ev_id,
                            reasoning=[f"{category} record {state.resource_id} still attributable to user, rule requires ANONYMIZE"],
                        ))
                        remediations.append(Remediation(
                            system_id=state.system_id, resource_id=state.resource_id,
                            operation="ANONYMIZE_RECORD", state="ANONYMIZED",
                            reasoning=["Anonymize record per rule"],
                        ))
                        verifications.append(Verification(
                            system_id=state.system_id, resource_id=state.resource_id,
                            operation="VERIFY_RECORD_ANONYMIZED", state="ANONYMIZED", evidence_id="",
                            reasoning=["Verify record anonymized after remediation"],
                        ))
                elif state.state == "ANONYMIZED":
                    verifications.append(Verification(
                        system_id=state.system_id, resource_id=state.resource_id,
                        operation="VERIFY_RECORD_ANONYMIZED", state="ANONYMIZED",
                        evidence_id=self._pick_evidence(state.evidence_ids, audit_dt),
                        reasoning=["Record confirmed anonymized per evidence"],
                    ))
            elif required_action == "RETAIN":
                retained_resources.append((state.system_id, state.resource_id, f"RETAIN required for {category}"))
                if state.state == "ABSENT":
                    findings.append(Finding(
                        system_id=state.system_id, resource_id=state.resource_id,
                        operation="REPORT_REMAINING_RECORD", state="PRESENT", evidence_id="",
                        reasoning=[f"{category} record {state.resource_id} is ABSENT but rule requires RETAIN"],
                    ))
                elif state.state == "PRESENT":
                    verifications.append(Verification(
                        system_id=state.system_id, resource_id=state.resource_id,
                        operation="VERIFY_RECORD_PRESENT", state="PRESENT",
                        evidence_id=self._pick_evidence(state.evidence_ids, audit_dt),
                        reasoning=["Retained record confirmed present per evidence"],
                    ))
        # Active data flow risk and verification
        for key, state in resource_states.items():
            if state.system_id == "integration_service" or (state.data_category == "MARKETING_PROFILE" and state.system_id != "integration_service"):
                if state.state == "ACTIVE":
                    findings.append(Finding(
                        system_id=state.system_id, resource_id=state.resource_id,
                        operation="REPORT_ACTIVE_DATA_FLOW", state="ACTIVE",
                        evidence_id=self._pick_evidence(state.evidence_ids, audit_dt),
                        reasoning=[f"Active data flow {state.resource_id} can copy or recreate user data"],
                    ))
                    remediations.append(Remediation(
                        system_id=state.system_id, resource_id=state.resource_id,
                        operation="DISABLE_DATA_FLOW", state="DISABLED",
                        reasoning=["Disable data flow to prevent resurrection"],
                    ))
                    verifications.append(Verification(
                        system_id=state.system_id, resource_id=state.resource_id,
                        operation="VERIFY_DATA_FLOW_DISABLED", state="DISABLED", evidence_id="",
                        reasoning=["Verify data flow disabled after remediation"],
                    ))
                elif state.state == "DISABLED":
                    verifications.append(Verification(
                        system_id=state.system_id, resource_id=state.resource_id,
                        operation="VERIFY_DATA_FLOW_DISABLED", state="DISABLED",
                        evidence_id=self._pick_evidence(state.evidence_ids, audit_dt),
                        reasoning=["Data flow confirmed disabled per evidence"],
                    ))

        # Resurrection risk analysis
        for key, state in resource_states.items():
            if state.state == "ABSENT" and self.resurrection_graph.has_resurrection_risk(state.system_id, state.resource_id):
                active_edges = self.resurrection_graph.get_active_edges()
                for edge in active_edges:
                    if f"{edge.target_system}|{edge.resource_id}" == key:
                        findings.append(Finding(
                            system_id=state.system_id, resource_id=state.resource_id,
                            operation="REPORT_ACTIVE_DATA_FLOW", state="ACTIVE",
                            evidence_id=edge.edge_id,
                            reasoning=[f"Active sync/import edge {edge.edge_id} can resurrect deleted record {state.resource_id}"],
                        ))
                        remediations.append(Remediation(
                            system_id=edge.source_system, resource_id=edge.resource_id,
                            operation="DISABLE_DATA_FLOW", state="DISABLED",
                            reasoning=["Disable data flow to prevent resurrection"],
                        ))
                        verifications.append(Verification(
                            system_id=edge.source_system, resource_id=edge.resource_id,
                            operation="VERIFY_DATA_FLOW_DISABLED", state="DISABLED", evidence_id="",
                            reasoning=["Verify data flow disabled after remediation"],
                        ))
                        break

        # Backup restore risk and verification
        for key, state in resource_states.items():
            if state.data_category == "BACKUP_ARCHIVE" or state.system_id == "backup_service":
                if state.state in ("ACTIVE", "PRESENT") or (state.record_data and (state.record_data.get("restore_allowed") == 1 or state.record_data.get("restore_allowed") == "1")):
                    findings.append(Finding(
                        system_id=state.system_id, resource_id=state.resource_id,
                        operation="REPORT_RESTORE_RISK", state="ACTIVE",
                        evidence_id=self._pick_evidence(state.evidence_ids, audit_dt),
                        reasoning=[f"Backup {state.resource_id} has restore access enabled — resurrection risk"],
                    ))
                    remediations.append(Remediation(
                        system_id=state.system_id, resource_id=state.resource_id,
                        operation="BLOCK_RESTORE", state="BLOCKED",
                        reasoning=["Block restore access to backup"],
                    ))
                    verifications.append(Verification(
                        system_id=state.system_id, resource_id=state.resource_id,
                        operation="VERIFY_RESTORE_BLOCKED", state="BLOCKED", evidence_id="",
                        reasoning=["Verify restore blocked after remediation"],
                    ))
                elif state.state == "BLOCKED":
                    verifications.append(Verification(
                        system_id=state.system_id, resource_id=state.resource_id,
                        operation="VERIFY_RESTORE_BLOCKED", state="BLOCKED",
                        evidence_id=self._pick_evidence(state.evidence_ids, audit_dt),
                        reasoning=["Restore access confirmed blocked per evidence"],
                    ))

        # Claim-vs-Proof contradiction analysis
        contradictions = self._analyze_claims(case, resource_states, audit_dt)
        reasoning_trace.append({
            "step": "claim_vs_proof",
            "contradiction_count": contradictions,
        })

        # Reasonable doubt scoring
        reasonable_doubt = self._compute_reasonable_doubt(
            findings, resource_states, contradictions, identity, intent
        )
        reasoning_trace.append({
            "step": "reasonable_doubt",
            "score": reasonable_doubt,
        })

        # Determine final status per Task 8: INCOMPLETE iff any finding exists, COMPLETE otherwise
        has_findings = len(findings) > 0

        if has_findings:
            deletion_status = "INCOMPLETE"
            steps = self._build_steps(findings, remediations, verifications, "INCOMPLETE")
        else:
            if len(verifications) > 0:
                deletion_status = "COMPLETE"
                steps = self._build_steps([], [], verifications, "COMPLETE")
            else:
                # Phase 3 Narrow Absence Proof for empty-finding cases
                user_ids = [k for k in identity.search_keys if k.startswith("user_")]
                proven_absence_step = None
                if user_ids:
                    uid = user_ids[0]
                    import re
                    m = re.match(r'user_0*(\d+)', uid)
                    if m:
                        num = int(m.group(1))
                        acct_id = f"account_{num:03d}" if num < 1000 else f"account_{num}"
                        # (3) deletion activity for that resource exists before audit_at
                        acts = self._load_activity_rows()
                        del_act = None
                        for a in acts:
                            if a.get("resource_id") == acct_id and a.get("event_type") == "DELETE_RECORD":
                                t = parse_utc(a.get("event_time"))
                                if t and t <= audit_dt:
                                    del_act = a
                                    break
                        if del_act:
                            # (1) & (2) snapshot/table exists with capture time <= audit_at, none of subject identifiers appear in it
                            matching_snap = None
                            for finfo in self.evidence_index.manifest:
                                fid = finfo.get("file_id")
                                c_at = parse_utc(finfo.get("captured_at"))
                                if c_at and c_at <= audit_dt and "customer_accounts" in finfo.get("file_path", ""):
                                    recs = [rec for rec in self.evidence_index.records if rec.file_id == fid]
                                    if not any(self.state_reconstructor._matches_search_keys(rec, identity.search_keys) for rec in recs):
                                        if matching_snap is None or c_at > parse_utc(matching_snap[1].get("captured_at")):
                                            matching_snap = (fid, finfo, c_at)
                            # (4) no later sync/restore/import before audit_at could recreate it
                            if matching_snap and not self.resurrection_graph.has_resurrection_risk("account_service", acct_id):
                                proven_absence_step = Verification(
                                    system_id="account_service", resource_id=acct_id,
                                    operation="VERIFY_RECORD_ABSENT", state="ABSENT",
                                    evidence_id=matching_snap[0],
                                    reasoning=["Narrow absence proof: confirmed absent across snapshots after deletion activity with zero resurrection risk"],
                                )

                if proven_absence_step:
                    deletion_status = "COMPLETE"
                    steps = self._build_steps([], [], [proven_absence_step], "COMPLETE")
                else:
                    deletion_status = "INCOMPLETE"
                    steps = self._build_steps([], [], [], "INCOMPLETE")

        return CaseResult(
            case_id=case_id, deletion_status=deletion_status, steps=steps,
            contradictions=contradictions, reasonable_doubt=reasonable_doubt,
            reasoning_trace=reasoning_trace,
            identity_result=identity, intent_result=intent,
        )

    def _evidence_matches_user(self, rec, search_keys):
        record_data = rec.record_data or {}
        for field in ["email", "requester_email", "owner_email", "customer_email", "match_key", "correlation_key", "subject_key", "lookup_key", "user_id", "customer_reference", "subject_reference", "subject_selector"]:
            val = record_data.get(field, "")
            if val and isinstance(val, str):
                from .common import normalize_email, sha256_hex
                if val in search_keys:
                    return True
                norm = normalize_email(val)
                if norm and norm in search_keys:
                    return True
                h = sha256_hex(norm) if norm else ""
                if h and h in search_keys:
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
        for ref_field in ["customer_reference", "user_id", "subject_reference"]:
            val = record_data.get(ref_field, "")
            if val and isinstance(val, str) and val in search_keys:
                return True
        return False

    def _load_activity_rows(self):
        if getattr(self, "_cached_activity_rows", None) is not None:
            return self._cached_activity_rows
        import os
        path = self.system_activity_csv_path
        if not path:
            candidates = ["dataset/system_activity.csv", "system_activity.csv"]
            for c in candidates:
                if os.path.exists(c):
                    path = c
                    break
        if not path or not os.path.exists(path):
            self._cached_activity_rows = []
        else:
            self._cached_activity_rows = load_csv(path)
        return self._cached_activity_rows

    def _build_rule_context(self, state, resource_states):
        rd = state.record_data or {}
        category = state.data_category
        context = {}
        has_identifiers = False
        for f in ["email", "phone", "full_name", "name", "email_hash", "requester_email", "owner_email", "customer_email", "requester_phone", "owner_phone"]:
            v = rd.get(f)
            if v and isinstance(v, str) and v.strip() and v.lower() not in ("null", "none", ""):
                has_identifiers = True
                break
        if isinstance(rd.get("emails"), list) and any(rd.get("emails")):
            has_identifiers = True
        context["attributable_to_user"] = has_identifiers or (state.state not in ("ANONYMIZED", "REDACTED"))

        excerpt = rd.get("message_excerpt", "") or rd.get("message", "") or rd.get("message_text", "") or ""
        shared_keywords = ["shared", "agent", "order", "customer context"]
        context["shared_context"] = any(kw in str(excerpt).lower() for kw in shared_keywords)

        context["attachment_only_subject"] = True
        if rd.get("shared") is True or rd.get("belongs_to_subject") is False:
            context["attachment_only_subject"] = False

        context["legal_hold_active"] = bool(rd.get("legal_hold") or rd.get("legal_hold_active"))

        context["restore_access_blockable"] = True
        if rd.get("restore_blockable") is False:
            context["restore_access_blockable"] = False

        context["retention_until"] = rd.get("retention_until")

        tombstone_needed = False
        if category == "ACCOUNT_TOMBSTONE":
            account_status = str(rd.get("account_status", "")).upper()
            if account_status in ("DELETED", "DELETION_PENDING", "INACTIVE"):
                tombstone_needed = True
            if rd.get("subject_reference") or rd.get("user_id") or rd.get("customer_reference"):
                tombstone_needed = True
        context["tombstone_needed"] = tombstone_needed

        context["log_contains_email"] = has_identifiers
        return context

    def _analyze_claims(self, case, resource_states, audit_dt):
        contradictions = 0
        reported_status = case.get("reported_status", "")
        if reported_status == "COMPLETE":
            for key, state in resource_states.items():
                if state.state in ("PRESENT", "ACTIVE"):
                    contradictions += 1
        return contradictions

    def _compute_reasonable_doubt(self, findings, resource_states, contradictions, identity, intent):
        score = 0.0
        if any(getattr(s, "is_unknown", False) for s in resource_states.values()):
            score += 0.3
        if contradictions > 0:
            score += min(0.4, 0.1 * contradictions)
        if len(findings) > 0:
            score += 0.1
        if identity is not None and getattr(identity, "status", "") != "RESOLVED":
            score += 0.3
        if intent is not None and getattr(intent, "confidence", 1.0) < 0.7:
            score += 0.2
        return min(1.0, score)

    def _build_steps(self, findings, remediations, verifications, deletion_status):
        from .common import OPERATION_PRECEDENCE
        phase_order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
        items = []
        for f in findings:
            if getattr(f, "evidence_id", ""):
                items.append(("FINDING", f))
        for r in remediations:
            items.append(("REMEDIATION", r))
        for v in verifications:
            items.append(("VERIFICATION", v))

        def sort_key(item):
            phase, obj = item
            op = obj.operation
            prec = OPERATION_PRECEDENCE.get(op, 999)
            return (phase_order[phase], prec, obj.system_id, obj.resource_id)

        items.sort(key=sort_key)

        steps = []
        step_no = 1
        for phase, obj in items:
            if deletion_status == "INCOMPLETE" and phase in ("REMEDIATION", "VERIFICATION"):
                eid = ""
            else:
                eid = getattr(obj, "evidence_id", "")
            step = {
                "step_no": step_no,
                "phase": phase,
                "system_id": obj.system_id,
                "resource_id": obj.resource_id,
                "operation": obj.operation,
                "state": obj.state,
                "evidence_id": eid,
            }
            steps.append(step)
            step_no += 1
        return steps
