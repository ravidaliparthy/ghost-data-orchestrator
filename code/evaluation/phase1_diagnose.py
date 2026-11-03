"""
Comprehensive Phase 1 Diagnostic Suite:
a) Manifest-wide Coverage Audit across all files in evidence_files.csv
b) Root-cause analysis of every false-negative gold finding
c) False positives by (operation, system_id), exact citation match rate, status distributions
d) Mined gold structure from sample_output.csv
"""

import os
import sys
import json
from collections import Counter, defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CODE_DIR = os.path.join(REPO_ROOT, "code")
DATASET_DIR = os.path.join(REPO_ROOT, "dataset")

if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

from engine.common import load_csv, parse_utc
from engine.identity_resolver import IdentityResolver
from engine.intent_classifier import IntentClassifier
from engine.evidence_index import EvidenceIndex
from engine.state_reconstructor import StateReconstructor
from engine.resurrection_graph import ResurrectionGraph
from engine.rules_engine import ConfigurableRulesEngine
from engine.evidence_evaluator import EvidenceEvaluator
from evaluation.main import evaluate_predictions, norm_steps

def get_file_type(path):
    p = path.lower()
    if p.endswith(".sql"): return "sql"
    if p.endswith(".json"): return "json"
    if p.endswith(".log"): return "log"
    if p.endswith(".pdf"): return "pdf"
    if p.endswith((".png", ".jpg", ".jpeg")): return "image"
    if p.endswith(".txt"): return "text"
    return "other"

def run_diagnostics():
    manifest_rows = load_csv(os.path.join(DATASET_DIR, "evidence_files.csv"))
    ei = EvidenceIndex(os.path.join(DATASET_DIR, "evidence_files.csv"), DATASET_DIR)
    ei.load()

    # =========================================================================
    # Part (a): Manifest-wide Coverage Audit
    # =========================================================================
    print("=" * 80)
    print("PHASE 1 (a): MANIFEST-WIDE COVERAGE AUDIT")
    print("=" * 80)

    facts_per_file = Counter()
    for rec in ei.records:
        facts_per_file[rec.file_id] += 1

    type_counts = Counter()
    type_facts = Counter()
    type_outcomes = defaultdict(Counter)

    print(f"{'File ID':<15} | {'Type':<8} | {'Outcome':<14} | {'Facts':<6} | {'Path'}")
    print("-" * 80)
    for row in manifest_rows:
        fid = row["file_id"]
        fpath = row["file_path"]
        ftype = get_file_type(fpath)
        fact_count = facts_per_file[fid]

        if ftype == "image":
            outcome = "unparsed (image)"
        elif fact_count > 0:
            outcome = "fully parsed"
        else:
            outcome = "unparsed"

        type_counts[ftype] += 1
        type_facts[ftype] += fact_count
        type_outcomes[ftype][outcome] += 1
        print(f"{fid:<15} | {ftype:<8} | {outcome:<14} | {fact_count:<6} | {fpath}")

    print("\n--- Summary by Evidence Type ---")
    print(f"{'Type':<10} | {'Total Files':<12} | {'Parsed Files':<14} | {'Total Facts':<12} | {'Avg Facts/File'}")
    print("-" * 70)
    for ftype, total in sorted(type_counts.items()):
        parsed = sum(cnt for out, cnt in type_outcomes[ftype].items() if "parsed" in out and "unparsed" not in out)
        facts = type_facts[ftype]
        avg = facts / total if total > 0 else 0
        print(f"{ftype:<10} | {total:<12} | {parsed:<14} | {facts:<12} | {avg:.1f}")

    # =========================================================================
    # Part (b), (c): Evaluator vs Sample Gold
    # =========================================================================
    ident = IdentityResolver(os.path.join(DATASET_DIR, "user_identities.csv"), os.path.join(DATASET_DIR, "user_audit_log.csv"))
    ident.load()
    sr = StateReconstructor(ei)
    rg = ResurrectionGraph(ei)
    re_ = ConfigurableRulesEngine(os.path.join(DATASET_DIR, "deletion_rules.csv"), os.path.join(CODE_DIR, "config", "rules.json"))
    re_.load()
    ev = EvidenceEvaluator(ident, IntentClassifier(False), ei, sr, rg, re_, system_activity_csv_path=os.path.join(DATASET_DIR, "system_activity.csv"))

    reqs = load_csv(os.path.join(DATASET_DIR, "sample_deletion_requests.csv"))
    gold = {r["case_id"]: (r["deletion_status"], norm_steps(r["steps_json"])) for r in load_csv(os.path.join(DATASET_DIR, "sample_output.csv"))}
    ev_manifest = {r["file_id"]: r for r in manifest_rows}

    pred_map = {}
    for r in reqs:
        res = ev.evaluate_case(r)
        steps = [s if isinstance(s, dict) else s.__dict__ for s in res.steps]
        pred_map[r["case_id"]] = (res.deletion_status, steps)

    metrics = evaluate_predictions(pred_map, gold)

    print("\n" + "=" * 80)
    print("PHASE 1 (b): FALSE-NEGATIVE GOLD FINDINGS ROOT CAUSE ANALYSIS")
    print("=" * 80)

    fn_findings = []
    fn_finding_causes = Counter()

    for r in reqs:
        cid = r["case_id"]
        gst, gsteps = gold[cid]
        pst, psteps = pred_map[cid]
        audit_dt = parse_utc(r["audit_at"])

        ures = ident.resolve(r["email"], r["requested_at"], r["audit_at"])

        gold_findings = [s for s in gsteps if s.get("phase") == "FINDING"]
        pred_findings = [s for s in psteps if s.get("phase") == "FINDING"]

        pred_f_keys = {(f["system_id"], f["resource_id"], f["operation"]) for f in pred_findings}

        for gf in gold_findings:
            key = (gf["system_id"], gf["resource_id"], gf["operation"])
            if key not in pred_f_keys:
                ev_id = gf.get("evidence_id", "")
                ev_type = get_file_type(ev_manifest.get(ev_id, {}).get("file_path", "")) if ev_id in ev_manifest else "activity/audit"
                
                # Diagnose root cause
                matching_recs = [rec for rec in ei.records if rec.resource_id == gf["resource_id"]]
                if not matching_recs:
                    cause = "file-not-parsed or resource-not-in-evidence"
                else:
                    # Check if linked to user search keys
                    linked = any(sr._matches_search_keys(rec, ures.search_keys) for rec in matching_recs)
                    if not linked:
                        cause = "parsed-but-subject-not-linked"
                    else:
                        # Check timestamp cutoff
                        valid_time = any(rec.captured_at and rec.captured_at <= audit_dt for rec in matching_recs)
                        if not valid_time:
                            cause = "time-excluded"
                        else:
                            cause = "state-misread or rule-not-matched"

                fn_findings.append({
                    "cid": cid,
                    "gf": gf,
                    "ev_type": ev_type,
                    "cause": cause
                })
                fn_finding_causes[cause] += 1
                print(f"[{cid}] Missed Finding: {gf['operation']} | sys={gf['system_id']} | res={gf['resource_id']} | ev={ev_id} ({ev_type})")
                print(f"      Cause: {cause}")

    print("\n--- Aggregated Missed Finding Causes ---")
    for cause, cnt in fn_finding_causes.most_common():
        print(f"  {cause:<45} | count: {cnt}")

    print("\n" + "=" * 80)
    print("PHASE 1 (c): EVALUATION BENCHMARK & CITATION ACCURACY")
    print("=" * 80)
    print(f"Status Accuracy: {metrics['status_matches']}/{metrics['total_cases']} ({metrics['status_accuracy']:.1%})")
    print(f"Step Precision (5-tuple): {metrics['step_p_5']:.3f}")
    print(f"Step Recall (5-tuple):    {metrics['step_r_5']:.3f}")
    print(f"Step F1 Score (5-tuple):  {metrics['step_f1_5']:.3f}")
    print(f"Exact Citation Matches:   {metrics['citations_matched']}/{metrics['citations_gold_total']} ({metrics['citation_accuracy']:.1%})")
    print(f"Predicted Status Dist:    {Counter(v[0] for v in pred_map.values())}")
    print(f"Gold Status Dist:         {Counter(v[0] for v in gold.values())}")

    print("\n" + "=" * 80)
    print("PHASE 1 (d): MINED GOLD STRUCTURE (FROM dataset/sample_output.csv)")
    print("=" * 80)
    from diff_samples import mine_gold_structure
    mine_gold_structure(gold)

if __name__ == "__main__":
    run_diagnostics()
