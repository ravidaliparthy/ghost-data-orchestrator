"""
Diagnostic harness comparing engine output on dataset/sample_deletion_requests.csv
against dataset/sample_output.csv.
Prints per case status match, false positives, false negatives,
aggregates by (operation, system_id) and by evidence type,
computes exact evidence_id match rate, and mines the gold structure.
"""

import os
import sys
import csv
import json
from collections import Counter, defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CODE_DIR = os.path.join(REPO_ROOT, "code")
DATASET_DIR = os.path.join(REPO_ROOT, "dataset")

if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

from engine.common import load_csv
from engine.identity_resolver import IdentityResolver
from engine.intent_classifier import IntentClassifier
from engine.evidence_index import EvidenceIndex
from engine.state_reconstructor import StateReconstructor
from engine.resurrection_graph import ResurrectionGraph
from engine.rules_engine import ConfigurableRulesEngine
from engine.evidence_evaluator import EvidenceEvaluator

def get_evidence_type(ev_id, ev_manifest):
    if not ev_id:
        return "none (future)"
    if ev_id.startswith("activity_"):
        return "activity"
    if ev_id.startswith("audit_"):
        return "audit"
    file_info = ev_manifest.get(ev_id)
    if not file_info:
        return "unknown"
    path = file_info.get("file_path", "").lower()
    if path.endswith(".sql"):
        return "sql"
    elif path.endswith(".pdf"):
        return "pdf"
    elif path.endswith((".png", ".jpg", ".jpeg")):
        return "image"
    elif path.endswith(".log"):
        return "log"
    elif path.endswith(".json"):
        return "json"
    elif path.endswith(".txt"):
        return "text"
    return "other"

def run_diff():
    identities_path = os.path.join(DATASET_DIR, "user_identities.csv")
    audit_log_path = os.path.join(DATASET_DIR, "user_audit_log.csv")
    evidence_files_csv = os.path.join(DATASET_DIR, "evidence_files.csv")
    rules_csv = os.path.join(DATASET_DIR, "deletion_rules.csv")
    activity_csv = os.path.join(DATASET_DIR, "system_activity.csv")
    samples_req_csv = os.path.join(DATASET_DIR, "sample_deletion_requests.csv")
    samples_gold_csv = os.path.join(DATASET_DIR, "sample_output.csv")

    ev_manifest_rows = load_csv(evidence_files_csv)
    ev_manifest = {r["file_id"]: r for r in ev_manifest_rows}

    identity_resolver = IdentityResolver(identities_path, audit_log_path)
    identity_resolver.load()
    intent_classifier = IntentClassifier(False)
    evidence_index = EvidenceIndex(evidence_files_csv, DATASET_DIR)
    evidence_index.load()
    state_reconstructor = StateReconstructor(evidence_index)
    resurrection_graph = ResurrectionGraph(evidence_index)
    rules_engine = ConfigurableRulesEngine(rules_csv, os.path.join(CODE_DIR, "config", "rules.json"))
    rules_engine.load()

    evaluator = EvidenceEvaluator(
        identity_resolver=identity_resolver,
        intent_classifier=intent_classifier,
        evidence_index=evidence_index,
        state_reconstructor=state_reconstructor,
        resurrection_graph=resurrection_graph,
        rules_engine=rules_engine,
        system_activity_csv_path=activity_csv,
    )

    sample_requests = load_csv(samples_req_csv)
    sample_requests.sort(key=lambda r: r.get("case_id", ""))

    gold_rows = load_csv(samples_gold_csv)
    gold_map = {}
    for r in gold_rows:
        cid = r.get("case_id", "")
        status = r.get("deletion_status", "")
        steps = json.loads(r.get("steps_json", "[]"))
        gold_map[cid] = (status, steps)

    pred_status_dist = Counter()
    gold_status_dist = Counter()

    fp_by_op_sys = Counter()
    fn_by_op_sys = Counter()
    fp_by_ev_type = Counter()
    fn_by_ev_type = Counter()

    # Match counts
    tp_5tuple = 0
    tp_exact_evidence = 0
    total_aligned_steps = 0

    status_matches = 0
    total_cases = len(sample_requests)

    mismatches = []

    print("=" * 80)
    print("SAMPLE-BY-SAMPLE DIAGNOSTIC REPORT")
    print("=" * 80)

    for case in sample_requests:
        cid = case.get("case_id", "")
        gold_status, gold_steps = gold_map.get(cid, ("UNKNOWN", []))
        gold_status_dist[gold_status] += 1

        result = evaluator.evaluate_case(case)
        pred_status = result.deletion_status
        pred_steps = result.steps or []
        pred_status_dist[pred_status] += 1

        status_match = (pred_status == gold_status)
        if status_match:
            status_matches += 1
        else:
            mismatches.append((cid, pred_status, gold_status, case))

        # Multiset matching for 5-tuple and 6-tuple
        gold_5 = [(s.get("phase"), s.get("operation"), s.get("system_id"), s.get("resource_id"), s.get("state")) for s in gold_steps]
        pred_5 = [(s.get("phase"), s.get("operation"), s.get("system_id"), s.get("resource_id"), s.get("state")) for s in pred_steps]

        gold_5_copy = list(gold_5)
        for p_idx, p in enumerate(pred_5):
            if p in gold_5_copy:
                g_idx = gold_5_copy.index(p)
                gold_5_copy.pop(g_idx)
                tp_5tuple += 1
                total_aligned_steps += 1
                # Check exact evidence_id match
                if pred_steps[p_idx].get("evidence_id", "") == gold_steps[g_idx].get("evidence_id", ""):
                    tp_exact_evidence += 1

        # Key: (phase, operation, system_id, resource_id, state, evidence_id)
        gold_keys = Counter(
            (s.get("phase"), s.get("operation"), s.get("system_id"), s.get("resource_id"), s.get("evidence_id", ""))
            for s in gold_steps
        )
        pred_keys = Counter(
            (s.get("phase"), s.get("operation"), s.get("system_id"), s.get("resource_id"), s.get("evidence_id", ""))
            for s in pred_steps
        )

        fp_steps = pred_keys - gold_keys
        fn_steps = gold_keys - pred_keys

        for step_k, count in fp_steps.items():
            phase, op, sys_id, res_id, ev_id = step_k
            fp_by_op_sys[(op, sys_id)] += count
            fp_by_ev_type[get_evidence_type(ev_id, ev_manifest)] += count

        for step_k, count in fn_steps.items():
            phase, op, sys_id, res_id, ev_id = step_k
            fn_by_op_sys[(op, sys_id)] += count
            fn_by_ev_type[get_evidence_type(ev_id, ev_manifest)] += count

        status_str = "MATCH" if status_match else f"MISMATCH (Pred: {pred_status} != Gold: {gold_status})"
        print(f"\n[{cid}] Status: {status_str} | Pred Steps: {len(pred_steps)} | Gold Steps: {len(gold_steps)}")

        if fp_steps:
            print(f"  False Positives ({sum(fp_steps.values())}):")
            for k, count in sorted(fp_steps.items()):
                ev_type = get_evidence_type(k[4], ev_manifest)
                print(f"    + [{count}x] phase={k[0]}, op={k[1]}, sys={k[2]}, res={k[3]}, ev={k[4]} ({ev_type})")
        if fn_steps:
            print(f"  False Negatives ({sum(fn_steps.values())}):")
            for k, count in sorted(fn_steps.items()):
                ev_type = get_evidence_type(k[4], ev_manifest)
                print(f"    - [{count}x] phase={k[0]}, op={k[1]}, sys={k[2]}, res={k[3]}, ev={k[4]} ({ev_type})")

    print("\n" + "=" * 80)
    print("STATUS ACCURACY SUMMARY & METRICS")
    print("=" * 80)
    print(f"Status Accuracy: {status_matches}/{total_cases} ({status_matches/total_cases*100:.1f}%)")
    print(f"Predicted Status Dist: {dict(pred_status_dist)}")
    print(f"Gold Status Dist:      {dict(gold_status_dist)}")

    if total_aligned_steps > 0:
        print(f"Exact evidence_id Match Rate on Matched Steps: {tp_exact_evidence}/{total_aligned_steps} ({tp_exact_evidence/total_aligned_steps*100:.1f}%)")

    if mismatches:
        print("\n" + "=" * 80)
        print("STATUS MISMATCHES ROOT CAUSE ANALYSIS")
        print("=" * 80)
        for cid, pred, gold, case in mismatches:
            print(f"\n--- {cid} (Pred={pred} vs Gold={gold}) ---")
            print(f"  Email: {case.get('email')}")
            print(f"  Reported Status: {case.get('reported_status')} at {case.get('reported_at')}")
            print(f"  Audit Cutoff: {case.get('audit_at')}")
            print(f"  Request Text: {case.get('request_text')[:100]}...")
            gold_steps = gold_map[cid][1]
            print(f"  Gold Steps ({len(gold_steps)}):")
            for gs in gold_steps:
                print(f"    * {gs.get('phase')} | {gs.get('operation')} | {gs.get('system_id')} | {gs.get('resource_id')} | ev={gs.get('evidence_id')}")

    print("\n" + "=" * 80)
    print("AGGREGATED FALSE POSITIVES BY (OPERATION, SYSTEM)")
    print("=" * 80)
    for (op, sys_id), count in fp_by_op_sys.most_common(15):
        print(f"  {op:<30} | {sys_id:<25} | count: {count}")

    print("\n" + "=" * 80)
    print("AGGREGATED FALSE NEGATIVES BY (OPERATION, SYSTEM)")
    print("=" * 80)
    for (op, sys_id), count in fn_by_op_sys.most_common(15):
        print(f"  {op:<30} | {sys_id:<25} | count: {count}")

    print("\n" + "=" * 80)
    print("AGGREGATED FALSE NEGATIVES BY EVIDENCE TYPE")
    print("=" * 80)
    for ev_type, count in fn_by_ev_type.most_common(10):
        print(f"  {ev_type:<20} | count: {count}")

    print("\n" + "=" * 80)
    print("AGGREGATED FALSE POSITIVES BY EVIDENCE TYPE")
    print("=" * 80)
    for ev_type, count in fp_by_ev_type.most_common(10):
        print(f"  {ev_type:<20} | count: {count}")

    print("\n" + "=" * 80)
    print("MINED GOLD STRUCTURE (FROM dataset/sample_output.csv)")
    print("=" * 80)
    mine_gold_structure(gold_map)

def mine_gold_structure(gold_map):
    # Analyze gold patterns
    finding_to_rem = defaultdict(Counter)
    rem_to_ver = defaultdict(Counter)
    status_step_counts = defaultdict(list)
    incomplete_cases_verifications = Counter()
    complete_case_ops = Counter()
    complete_case_systems = Counter()

    for cid, (status, steps) in gold_map.items():
        status_step_counts[status].append(len(steps))

        if status == "INCOMPLETE":
            findings = [s for s in steps if s.get("phase") == "FINDING"]
            remediations = [s for s in steps if s.get("phase") == "REMEDIATION"]
            verifications = [s for s in steps if s.get("phase") == "VERIFICATION"]

            # Map findings to remediations on same resource
            for f in findings:
                f_res = f.get("resource_id")
                matching_rems = [r for r in remediations if r.get("resource_id") == f_res]
                for r in matching_rems:
                    finding_to_rem[f.get("operation")][r.get("operation")] += 1
                    matching_vers = [v for v in verifications if v.get("resource_id") == f_res]
                    for v in matching_vers:
                        rem_to_ver[r.get("operation")][v.get("operation")] += 1

            # Check if verifications in INCOMPLETE contain non-remediated resources
            remediated_res = {r.get("resource_id") for r in remediations}
            for v in verifications:
                if v.get("resource_id") not in remediated_res:
                    incomplete_cases_verifications[v.get("operation")] += 1

        elif status == "COMPLETE":
            for s in steps:
                complete_case_ops[s.get("operation")] += 1
                complete_case_systems[s.get("system_id")] += 1

    print("\n1. Finding -> Remediation -> Verification Op Flow in INCOMPLETE cases:")
    for f_op, rem_counts in finding_to_rem.items():
        for r_op, count in rem_counts.items():
            vers = rem_to_ver.get(r_op, {})
            ver_str = ", ".join(f"{v_op} ({cnt})" for v_op, cnt in vers.items())
            print(f"  {f_op} -> {r_op} ({count}x) -> {ver_str}")

    print("\n2. Verification steps in INCOMPLETE cases for NON-remediated resources (compliant / retained records):")
    if incomplete_cases_verifications:
        for op, count in incomplete_cases_verifications.items():
            print(f"  {op}: {count}x")
    else:
        print("  NONE! In INCOMPLETE cases, VERIFICATION steps exist ONLY for remediated resources!")

    print("\n3. COMPLETE Cases Operations & Systems Verified:")
    print("  Operations:")
    for op, cnt in complete_case_ops.most_common():
        print(f"    {op}: {cnt}x")
    print("  Systems:")
    for sys_id, cnt in complete_case_systems.most_common():
        print(f"    {sys_id}: {cnt}x")

    print("\n4. Typical Step Counts by Status:")
    for status, counts in status_step_counts.items():
        avg = sum(counts) / len(counts) if counts else 0
        print(f"  {status:<15}: count={len(counts)}, min={min(counts)}, max={max(counts)}, avg={avg:.1f}")

if __name__ == "__main__":
    run_diff()

