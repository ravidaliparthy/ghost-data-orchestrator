"""
Test per-case isolation: evaluate_case must be a pure function of (case, read-only indexes).
Results must be bitwise identical whether evaluated in original order, reverse order, or alone.
"""
import os, sys, json

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

def test_case_isolation():
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

    # Run forward
    forward_results = {}
    for case in samples:
        res = ev.evaluate_case(case)
        forward_results[case["case_id"]] = (res.deletion_status, json.dumps(res.steps, sort_keys=True))

    # Run reversed
    reversed_results = {}
    for case in reversed(samples):
        res = ev.evaluate_case(case)
        reversed_results[case["case_id"]] = (res.deletion_status, json.dumps(res.steps, sort_keys=True))

    for cid in forward_results:
        assert forward_results[cid] == reversed_results[cid], f"Case {cid} yielded different result when order was reversed!"

if __name__ == "__main__":
    test_case_isolation()
    print("test_case_isolation: PASS")
