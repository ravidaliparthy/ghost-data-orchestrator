"""
Evaluation and Metrics Runner for HackerRank Orchestrate: Ghost Data Still Exists.
Computes case status accuracy, row accuracy, step precision/recall/F1 (with and without evidence_id),
field-level accuracy, sequence accuracy (LCS ratio + exact order), citation accuracy,
and per-sample error attribution. Outputs Markdown report and tracks checkpoint metrics history.
"""

import csv
import json
import os
import sys
from typing import Dict, List, Tuple, Any

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CODE = os.path.join(ROOT, "code")
if CODE not in sys.path:
    sys.path.insert(0, CODE)

DATASET = os.path.join(ROOT, "dataset")

def load_csv(path: str) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def norm_steps(steps_json_str: str) -> List[Dict[str, Any]]:
    if not steps_json_str:
        return []
    try:
        arr = json.loads(steps_json_str)
        return arr if isinstance(arr, list) else []
    except Exception:
        return []

def lcs_length(a: list, b: list) -> int:
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m):
        for j in range(n):
            if a[i] == b[j]:
                dp[i + 1][j + 1] = dp[i][j] + 1
            else:
                dp[i + 1][j + 1] = max(dp[i + 1][j], dp[i][j + 1])
    return dp[m][n]

def evaluate_predictions(pred_map: Dict[str, Tuple[str, List[Dict[str, Any]]]],
                         gold_map: Dict[str, Tuple[str, List[Dict[str, Any]]]]) -> Dict[str, Any]:
    total_cases = len(gold_map)
    status_matches = 0
    row_matches = 0
    
    total_gold_steps = 0
    total_pred_steps = 0
    
    # 5-tuple: (phase, system_id, resource_id, operation, state)
    tp_5tuple = 0
    # 6-tuple: (phase, system_id, resource_id, operation, state, evidence_id)
    tp_6tuple = 0
    
    # Aligned step field matches
    field_counts = {
        "step_no": 0, "phase": 0, "system_id": 0, "resource_id": 0,
        "operation": 0, "state": 0, "evidence_id": 0, "total_aligned": 0
    }
    
    total_lcs_score = 0.0
    exact_order_count = 0
    
    citations_matched = 0
    citations_gold_total = 0
    
    error_attribution = []
    
    for cid, (gold_status, gold_steps) in gold_map.items():
        pred_status, pred_steps = pred_map.get(cid, ("NOT_FOUND", []))
        
        status_match = (pred_status == gold_status)
        if status_match:
            status_matches += 1
            
        exact_match = False
        if status_match and len(gold_steps) == len(pred_steps):
            if all(g == p for g, p in zip(gold_steps, pred_steps)):
                exact_match = True
                row_matches += 1
                
        total_gold_steps += len(gold_steps)
        total_pred_steps += len(pred_steps)
        
        # Multiset matching for 5-tuple
        gold_5 = [(s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"]) for s in gold_steps]
        pred_5 = [(s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"]) for s in pred_steps]
        
        gold_5_copy = list(gold_5)
        case_tp_5 = 0
        for p in pred_5:
            if p in gold_5_copy:
                gold_5_copy.remove(p)
                case_tp_5 += 1
        tp_5tuple += case_tp_5
        
        # Multiset matching for 6-tuple
        gold_6 = [(s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"], s.get("evidence_id", "")) for s in gold_steps]
        pred_6 = [(s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"], s.get("evidence_id", "")) for s in pred_steps]
        
        gold_6_copy = list(gold_6)
        case_tp_6 = 0
        for p in pred_6:
            if p in gold_6_copy:
                gold_6_copy.remove(p)
                case_tp_6 += 1
        tp_6tuple += case_tp_6
        
        # Step alignment (greedy by resource_id/system_id or position)
        used_pred = set()
        aligned_pairs = []
        for g_idx, g in enumerate(gold_steps):
            best_p_idx = -1
            best_match_score = -1
            for p_idx, p in enumerate(pred_steps):
                if p_idx in used_pred:
                    continue
                score = 0
                if g.get("resource_id") == p.get("resource_id"): score += 3
                if g.get("system_id") == p.get("system_id"): score += 2
                if g.get("phase") == p.get("phase"): score += 1
                if g.get("operation") == p.get("operation"): score += 1
                if score > best_match_score:
                    best_match_score = score
                    best_p_idx = p_idx
            if best_p_idx != -1 and best_match_score >= 3:
                used_pred.add(best_p_idx)
                aligned_pairs.append((g, pred_steps[best_p_idx]))
                
        for g, p in aligned_pairs:
            field_counts["total_aligned"] += 1
            for k in ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]:
                if g.get(k) == p.get(k):
                    field_counts[k] += 1
            if g.get("evidence_id"):
                citations_gold_total += 1
                if g.get("evidence_id") == p.get("evidence_id"):
                    citations_matched += 1
                    
        # Sequence accuracy: LCS ratio
        g_keys = [(s["system_id"], s["resource_id"]) for s in gold_steps]
        p_keys = [(s["system_id"], s["resource_id"]) for s in pred_steps]
        denom = max(len(g_keys), len(p_keys), 1)
        lcs_len = lcs_length(g_keys, p_keys)
        case_lcs = lcs_len / denom if max(len(g_keys), len(p_keys)) > 0 else 1.0
        total_lcs_score += case_lcs
        
        # Exact order rate
        if case_lcs == 1.0 and len(g_keys) == len(p_keys):
            exact_order_count += 1
            
        # Error attribution
        if not exact_match or not status_match:
            errors = []
            if not status_match:
                errors.append(f"Status mismatch: expected {gold_status}, got {pred_status}")
            if len(pred_steps) < len(gold_steps):
                errors.append(f"Missing steps ({len(gold_steps) - len(pred_steps)} missing)")
            elif len(pred_steps) > len(gold_steps):
                errors.append(f"Extra steps ({len(pred_steps) - len(gold_steps)} extra)")
            
            # Check for misaligned operations / states
            for g, p in aligned_pairs:
                if g.get("operation") != p.get("operation"):
                    errors.append(f"Wrong op on {g.get('resource_id')}: exp {g.get('operation')} got {p.get('operation')}")
                if g.get("state") != p.get("state"):
                    errors.append(f"Wrong state on {g.get('resource_id')}: exp {g.get('state')} got {p.get('state')}")
                if g.get("evidence_id") != p.get("evidence_id"):
                    errors.append(f"Wrong evidence on {g.get('resource_id')}: exp '{g.get('evidence_id')}' got '{p.get('evidence_id')}'")
                    
            error_attribution.append({
                "case_id": cid,
                "status_match": status_match,
                "pred_status": pred_status,
                "gold_status": gold_status,
                "gold_steps_count": len(gold_steps),
                "pred_steps_count": len(pred_steps),
                "errors": errors
            })
            
    # Step metrics 5-tuple
    p_5 = tp_5tuple / total_pred_steps if total_pred_steps > 0 else 0.0
    r_5 = tp_5tuple / total_gold_steps if total_gold_steps > 0 else 0.0
    f1_5 = 2 * p_5 * r_5 / (p_5 + r_5) if (p_5 + r_5) > 0 else 0.0
    
    # Step metrics 6-tuple
    p_6 = tp_6tuple / total_pred_steps if total_pred_steps > 0 else 0.0
    r_6 = tp_6tuple / total_gold_steps if total_gold_steps > 0 else 0.0
    f1_6 = 2 * p_6 * r_6 / (p_6 + r_6) if (p_6 + r_6) > 0 else 0.0
    
    # Field accuracy
    n_aligned = max(field_counts["total_aligned"], 1)
    field_acc = {k: field_counts[k] / n_aligned for k in ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]}
    
    return {
        "total_cases": total_cases,
        "status_accuracy": status_matches / total_cases if total_cases > 0 else 0.0,
        "status_matches": status_matches,
        "row_accuracy": row_matches / total_cases if total_cases > 0 else 0.0,
        "row_matches": row_matches,
        "step_p_5": p_5,
        "step_r_5": r_5,
        "step_f1_5": f1_5,
        "step_p_6": p_6,
        "step_r_6": r_6,
        "step_f1_6": f1_6,
        "field_accuracy": field_acc,
        "total_aligned_steps": field_counts["total_aligned"],
        "mean_lcs_ratio": total_lcs_score / total_cases if total_cases > 0 else 0.0,
        "exact_order_rate": exact_order_count / total_cases if total_cases > 0 else 0.0,
        "citation_accuracy": citations_matched / citations_gold_total if citations_gold_total > 0 else 0.0,
        "citations_matched": citations_matched,
        "citations_gold_total": citations_gold_total,
        "error_attribution": error_attribution
    }

def run_sample_evaluation() -> Dict[str, Any]:
    from engine.identity_resolver import IdentityResolver
    from engine.evidence_index import EvidenceIndex
    from engine.state_reconstructor import StateReconstructor
    from engine.resurrection_graph import ResurrectionGraph
    from engine.rules_engine import ConfigurableRulesEngine
    from engine.evidence_evaluator import EvidenceEvaluator
    from engine.intent_classifier import IntentClassifier
    
    ident = IdentityResolver(os.path.join(DATASET, "user_identities.csv"), os.path.join(DATASET, "user_audit_log.csv"))
    ident.load()
    ei = EvidenceIndex(os.path.join(DATASET, "evidence_files.csv"), DATASET)
    ei.load()
    sr = StateReconstructor(ei)
    rg = ResurrectionGraph(ei)
    re_ = ConfigurableRulesEngine(os.path.join(DATASET, "deletion_rules.csv"), os.path.join(CODE, "config", "rules.json"))
    re_.load()
    ev = EvidenceEvaluator(ident, IntentClassifier(False), ei, sr, rg, re_, system_activity_csv_path=os.path.join(DATASET, "system_activity.csv"))
    
    reqs = load_csv(os.path.join(DATASET, "sample_deletion_requests.csv"))
    gold = load_csv(os.path.join(DATASET, "sample_output.csv"))
    
    gold_map = {}
    for r in gold:
        gold_map[r["case_id"]] = (r["deletion_status"], norm_steps(r["steps_json"]))
        
    pred_map = {}
    for r in reqs:
        res = ev.evaluate_case(r)
        steps = []
        for s in res.steps:
            d = s if isinstance(s, dict) else s.__dict__
            steps.append({
                "step_no": d["step_no"],
                "phase": d["phase"],
                "system_id": d["system_id"],
                "resource_id": d["resource_id"],
                "operation": d["operation"],
                "state": d["state"],
                "evidence_id": d["evidence_id"],
            })
        pred_map[r["case_id"]] = (res.deletion_status, steps)
        
    return evaluate_predictions(pred_map, gold_map)

def generate_report_markdown(metrics: Dict[str, Any], checkpoint_name: str = "cp00") -> str:
    lines = []
    lines.append(f"# HackerRank Orchestrate: Evaluation Report ({checkpoint_name})\n")
    lines.append("## Executive Summary\n")
    lines.append(f"- **Sample Cases**: {metrics['total_cases']}")
    lines.append(f"- **Case Status Accuracy**: {metrics['status_matches']}/{metrics['total_cases']} ({metrics['status_accuracy']:.1%})")
    lines.append(f"- **Row (Exact Steps) Accuracy**: {metrics['row_matches']}/{metrics['total_cases']} ({metrics['row_accuracy']:.1%})")
    lines.append(f"- **Step Precision / Recall / F1 (5-tuple: phase, sys, res, op, state)**: P={metrics['step_p_5']:.3f}, R={metrics['step_r_5']:.3f}, F1={metrics['step_f1_5']:.3f}")
    lines.append(f"- **Step Precision / Recall / F1 (6-tuple: including evidence_id)**: P={metrics['step_p_6']:.3f}, R={metrics['step_r_6']:.3f}, F1={metrics['step_f1_6']:.3f}")
    lines.append(f"- **Sequence Accuracy (Mean LCS Ratio)**: {metrics['mean_lcs_ratio']:.3f}")
    lines.append(f"- **Exact Order Rate**: {metrics['exact_order_rate']:.1%}")
    lines.append(f"- **Evidence Citation Accuracy**: {metrics['citations_matched']}/{metrics['citations_gold_total']} ({metrics['citation_accuracy']:.1%})\n")
    
    lines.append("## Field-Level Accuracy Over Aligned Steps\n")
    lines.append("| Field | Match Rate | Matched / Aligned |")
    lines.append("|---|---|---|")
    fa = metrics["field_accuracy"]
    tot = metrics["total_aligned_steps"]
    for f in ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]:
        rate = fa.get(f, 0.0)
        lines.append(f"| `{f}` | {rate:.1%} | {int(round(rate * tot))} / {tot} |")
    lines.append("\n")
    
    lines.append("## Error Attribution per Sample\n")
    lines.append(f"Mismatches observed on {len(metrics['error_attribution'])} cases:\n")
    lines.append("| Case | Status (Exp vs Got) | Steps (Exp vs Got) | Primary Causes |")
    lines.append("|---|---|---|---|")
    for err in metrics["error_attribution"]:
        cid = err["case_id"]
        st = f"{err['gold_status']} vs {err['pred_status']}"
        cnt = f"{err['gold_steps_count']} vs {err['pred_steps_count']}"
        causes = "; ".join(err["errors"][:3])
        if len(err["errors"]) > 3:
            causes += f" (+{len(err['errors'])-3} more)"
        lines.append(f"| {cid} | {st} | {cnt} | {causes} |")
    lines.append("\n")
    
    return "\n".join(lines)

def main():
    print("Running sample evaluation...")
    metrics = run_sample_evaluation()
    print("\n=== EVALUATION RESULTS ===")
    print(f"Status Accuracy: {metrics['status_matches']}/{metrics['total_cases']} ({metrics['status_accuracy']:.1%})")
    print(f"Row Accuracy: {metrics['row_matches']}/{metrics['total_cases']} ({metrics['row_accuracy']:.1%})")
    print(f"Step F1 (5-tuple): {metrics['step_f1_5']:.3f} (P={metrics['step_p_5']:.3f}, R={metrics['step_r_5']:.3f})")
    print(f"Step F1 (6-tuple): {metrics['step_f1_6']:.3f} (P={metrics['step_p_6']:.3f}, R={metrics['step_r_6']:.3f})")
    print(f"Mean LCS Ratio: {metrics['mean_lcs_ratio']:.3f}, Exact Order Rate: {metrics['exact_order_rate']:.1%}")
    print(f"Citation Accuracy: {metrics['citations_matched']}/{metrics['citations_gold_total']} ({metrics['citation_accuracy']:.1%})")
    
    md = generate_report_markdown(metrics, "cp00")
    report_path = os.path.join(CODE, "evaluation", "evaluation_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"\nReport written to: {report_path}")

if __name__ == "__main__":
    main()
