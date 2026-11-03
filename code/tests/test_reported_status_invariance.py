"""
Test that reported_status in deletion requests is treated strictly as a claim.
Flipping reported_status between COMPLETE and NOT_STARTED must never alter the engine's verdict.
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
from engine.common import load_csv

def test_reported_status_invariance():
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

    samples = load_csv(os.path.join(dataset_dir, "sample_deletion_requests.csv"))[:10]
    for case in samples:
        original_res = ev.evaluate_case(case)
        
        # Test 1: flip to NOT_STARTED
        flipped_case_ns = copy.deepcopy(case)
        flipped_case_ns["reported_status"] = "NOT_STARTED"
        res_ns = ev.evaluate_case(flipped_case_ns)
        assert res_ns.deletion_status == original_res.deletion_status, f"{case['case_id']} status changed when reported_status flipped to NOT_STARTED"
        assert len(res_ns.steps) == len(original_res.steps), f"{case['case_id']} steps changed when reported_status flipped to NOT_STARTED"

        # Test 2: flip to COMPLETE
        flipped_case_comp = copy.deepcopy(case)
        flipped_case_comp["reported_status"] = "COMPLETE"
        res_comp = ev.evaluate_case(flipped_case_comp)
        assert res_comp.deletion_status == original_res.deletion_status, f"{case['case_id']} status changed when reported_status flipped to COMPLETE"
        assert len(res_comp.steps) == len(original_res.steps), f"{case['case_id']} steps changed when reported_status flipped to COMPLETE"

if __name__ == "__main__":
    test_reported_status_invariance()
    print("test_reported_status_invariance: PASS")
