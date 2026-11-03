import csv, json, os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CODE = os.path.join(ROOT, "code")
sys.path.insert(0, CODE)
DATASET = os.path.join(ROOT, "dataset")

from engine.common import parse_utc
from engine.intent_classifier import IntentClassifier
from engine.identity_resolver import IdentityResolver
from engine.evidence_index import EvidenceIndex
from engine.state_reconstructor import StateReconstructor
from engine.resurrection_graph import ResurrectionGraph
from engine.rules_engine import ConfigurableRulesEngine
from engine.evidence_evaluator import EvidenceEvaluator

def load_csv(p):
    with open(p, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))
def build():
    ident = IdentityResolver(os.path.join(DATASET,"user_identities.csv"), os.path.join(DATASET,"user_audit_log.csv"))
    ident.load()
    ei = EvidenceIndex(os.path.join(DATASET,"evidence_files.csv"), DATASET)
    ei.load()
    sr = StateReconstructor(ei)
    rg = ResurrectionGraph(ei)
    re_ = ConfigurableRulesEngine(os.path.join(DATASET,"deletion_rules.csv"), os.path.join(CODE,"config","rules.json"))
    re_.load()
    ev = EvidenceEvaluator(ident, IntentClassifier(False), ei, sr, rg, re_, system_activity_csv_path=os.path.join(DATASET,"system_activity.csv"))
    return ev, ei

def norm_steps(s):
    arr = json.loads(s) if s else []
    out = []
    for st in arr:
        out.append((st["step_no"], st["phase"], st["system_id"], st["resource_id"], st["operation"], st["state"], st["evidence_id"]))
    return out

def main():
    ev, ei = build()
    reqs = load_csv(os.path.join(DATASET,"sample_deletion_requests.csv"))
    gold = load_csv(os.path.join(DATASET,"sample_output.csv"))
    gold_map = {r["case_id"]: r for r in gold}
    results = {}
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
        results[r["case_id"]] = (res.deletion_status, steps)
    status_ok = 0; step_exact = 0; total = len(reqs)
    for r in reqs:
        cid = r["case_id"]
        g = gold_map[cid]
        g_status = g["deletion_status"]
        g_steps = norm_steps(g["steps_json"])
        p_status, p_steps_list = results[cid]
        p_steps = [(s["step_no"], s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"], s["evidence_id"]) for s in p_steps_list]
        if p_status == g_status:
            status_ok += 1
        if p_steps == g_steps:
            step_exact += 1
        else:
            print("MISMATCH", cid, "status", p_status, "vs", g_status, "steps", len(p_steps), "vs", len(g_steps))
            # show first diff
            for i,(a,b) in enumerate(zip(p_steps,g_steps)):
                if a!=b:
                    print("  first diff at", i, "got", a, "exp", b); break
    print("status accuracy:", status_ok, "/", total)
    print("exact step match:", step_exact, "/", total)

if __name__ == "__main__":
    main()

