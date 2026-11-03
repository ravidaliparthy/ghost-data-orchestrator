"""
ResurrectionGraph — Sync/Restore Edge Modeling.

Models sync jobs, imports, replication, and backup restores as directed edges
in a graph. A deleted record with an active inbound edge can be resurrected.

Security principles:
- Active sync/import/restore edge to an absent record = resurrection risk.
- Edges are only active if corroborated by evidence captured at or before audit_at.
- Scheduled-but-not-executed restores do not create immediate risk.
"""

from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from .common import parse_utc, redact_for_log


class ResurrectionEdge:
    def __init__(self, edge_id, source_system, target_system, resource_id,
                 event_type, reported_result, event_time, corroborated=False,
                 active_at_audit_at=False):
        self.edge_id = edge_id
        self.source_system = source_system
        self.target_system = target_system
        self.resource_id = resource_id
        self.event_type = event_type
        self.reported_result = reported_result
        self.event_time = event_time
        self.corroborated = corroborated
        self.active_at_audit_at = active_at_audit_at


class ResurrectionGraph:
    def __init__(self, evidence_index):
        self.evidence_index = evidence_index
        self.edges: List[ResurrectionEdge] = []

    def build(self, audit_at, system_activity_rows: List[Dict[str, Any]]) -> List[ResurrectionEdge]:
        """
        Build resurrection edges from system_activity rows.
        Only edges with event_time <= audit_at are considered.
        An edge is active at audit_at if the newest evidence for the connector
        shows enabled=1 or SUCCESS, corroborated by evidence.
        """
        audit_dt = parse_utc(audit_at)
        self.edges = []

        # Event types that can copy or recreate data
        recreating_types = {
            "SYNC_RECORD", "INDEX_RECORD", "UPDATE_RECORD", "RESTORE_RECORD",
            "REPLICATE", "COPY_RECORD", "IMPORT_RECORD",
        }

        for row in system_activity_rows:
            event_time = parse_utc(row.get("event_time", ""))
            if event_time is None or event_time > audit_dt:
                continue

            event_type = row.get("event_type", "")
            if event_type not in recreating_types:
                continue

            source_system = row.get("source_system", "")
            target_system = row.get("target_system", "")
            resource_id = row.get("resource_id", "")
            reported_result = row.get("reported_result", "")
            activity_id = row.get("activity_id", "")

            # Check if this edge is corroborated by evidence
            corroborated = self._is_corroborated(activity_id, event_type, resource_id, source_system, target_system, audit_dt)
            active_at_audit_at = corroborated and reported_result in ("SUCCESS", "ACTIVE", "ENABLED")

            edge = ResurrectionEdge(
                edge_id=activity_id,
                source_system=source_system,
                target_system=target_system,
                resource_id=resource_id,
                event_type=event_type,
                reported_result=reported_result,
                event_time=event_time,
                corroborated=corroborated,
                active_at_audit_at=active_at_audit_at,
            )
            self.edges.append(edge)

        return self.edges

    def _is_corroborated(self, activity_id, event_type, resource_id, source_system, target_system, audit_dt):
        """Check if an activity claim is corroborated by evidence files."""
        # Look for evidence matching this resource in the target system
        evidence = self.evidence_index.search_by_resource(target_system, resource_id)
        if not evidence:
            # Also try by resource_id alone
            evidence = self.evidence_index.search_by_resource_id(resource_id)

        # Check if any evidence was captured at or before audit_dt
        for rec in evidence:
            if rec.captured_at is not None and rec.captured_at <= audit_dt:
                if rec.extraction_quality in ("HIGH", "MEDIUM"):
                    return True
        return False

    def has_resurrection_risk(self, system_id: str, resource_id: str) -> bool:
        """Check if a resource has an active resurrection edge targeting it."""
        target_key = f"{system_id}|{resource_id}"
        for edge in self.edges:
            if edge.active_at_audit_at and f"{edge.target_system}|{edge.resource_id}" == target_key:
                return True
        return False

    def get_active_edges(self) -> List[ResurrectionEdge]:
        """Return all edges active at audit_at."""
        return [e for e in self.edges if e.active_at_audit_at]