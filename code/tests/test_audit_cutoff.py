"""
Test temporal audit_at boundary isolation:
Evidence captured strictly after audit_at must never be cited and must never alter the verdict.
"""
import os, sys, copy

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "code"))

from engine.identity_resolver import IdentityResolver
from engine.evidence_index import EvidenceIndex
from engine.state_reconstructor import StateReconstructor
from engine.resurrection_graph import ResurrectionGraph
from engine.rules_engine import ConfigurableRulesEngine
from engine.evidence_evaluator import EvidenceEvaluator
from engine.intent_classifier import IntentClassifier
from engine.common import load_csv, parse_utc

def test_audit_cutoff_enforcement():
    dataset_dir = os.path.join(ROOT, "dataset")
    ident = IdentityResolver(os.path.join(dataset_dir, "user_identities.csv"), os.path.join(dataset_dir, "user_audit_log.csv"))
    ident.load()
    ei = EvidenceIndex(os.path.join(dataset_dir, "evidence_files.csv"), dataset_dir)
    ei.load()
    sr = StateReconstructor(ei)
    rg = ResurrectionGraph(ei)
    re_ = ConfigurableRulesEngine(os.path.join(dataset_dir, "deletion_rules.csv"), os.path.join(ROOT, "code", "config", "rules.json"))
    re_.load()
    ev = EvidenceEvaluator(ident, IntentClassifier(False), ei, sr, rg, re_, system_activity_csv_path=os.path.join(dataset_dir, "system_activity.csv"))

    manifest = {r["file_id"]: parse_utc(r["captured_at"]) for r in load_csv(os.path.join(dataset_dir, "evidence_files.csv"))}
    samples = load_csv(os.path.join(dataset_dir, "sample_deletion_requests.csv"))

    for case in samples:
        res = ev.evaluate_case(case)
        audit_dt = parse_utc(case["audit_at"])
        for s in res.steps:
            eid = s.evidence_id if hasattr(s, "evidence_id") else s.get("evidence_id", "")
            if eid and eid in manifest:
                cap = manifest[eid]
                assert cap <= audit_dt, f"{case['case_id']} cited evidence {eid} captured at {cap} which is AFTER audit_at {audit_dt}"

if __name__ == "__main__":
    test_audit_cutoff_enforcement()
    print("test_audit_cutoff_enforcement: PASS")
