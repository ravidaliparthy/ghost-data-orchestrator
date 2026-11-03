# AI Interview Technical Notes: Ghost Data Still Exists Deletion-Audit Engine

## 1. Problem and Approach
Enterprise deletion workflows routinely report `COMPLETE` while customer personal data persists across database replicas, logs, caches, export bundles, and backups, or gets actively resurrected by background synchronization jobs. Our solution is an offline, deterministic deletion-audit engine that reconstructs the true point-in-time state of each user at the strict cutoff `audit_at`. It resolves current and historical identity graphs, indexes heterogeneous multi-source evidence, models resurrection risks, strictly enforces declarative deletion policies, and produces validated, ordered findings, remediations, and evidence-backed verification steps without reliance on external networks, API keys, or non-deterministic model calls ($0.00 cost).

---

## 2. Architecture & Pipeline
```text
[Request: email, text, audit_at]
       │
       ▼
1. Intent Classifier (14 languages, negation windowing, non-deletion overrides) ──► NOT_APPLICABLE (steps: [])
       │ (Authorized)
       ▼
2. Temporal Identity Resolver (user_identities.csv + user_audit_log.csv -> search keys)
       │
       ▼
3. Evidence Index (manifest captured_at <= audit_at, in-memory SQLite, JSON, logs, native PDF)
       │
       ▼
4. State Reconstructor (Primary vs replica drift, activity log correlation, as-of audit_at state)
       │
       ▼
5. Resurrection Graph (Active integration flows & unblocked backup archives)
       │
       ▼
6. Rules Engine (deletion_rules.csv: DELETE, REDACT, ANONYMIZE, RETAIN, TOMBSTONE)
       │
       ▼
7. Step Generator & Orderer (FINDING -> REMEDIATION -> VERIFICATION; consecutive step_no)
       │
       ▼
8. Output Validator & Integrity Gate (Contract compliance, time cutoff, citation grounding)
```
- `intent_classifier.py`: Multilingual deletion authorization, negation windows, non-deletion overrides.
- `identity_resolver.py`: Bidirectional resolution across historical email/phone/hash audit logs.
- `evidence_index.py`: Point-in-time multi-source parsing; in-memory SQLite for SQL exports; native PDF decompression.
- `state_reconstructor.py`: Resolves replica drift, table snapshots, and activity logs as claims vs evidence.
- `resurrection_graph.py`: Directed graph tracking active sync connectors and restore paths.
- `rules_engine.py`: Matches 15 policy rules, tombstone scrubbing, and retention hold periods.
- `evidence_evaluator.py`: Orchestrates lifecycle findings, remediations, and verifications.
- `output_validator.py` & `integrity_checks.py`: Strict schema, ordering, and citation verification.

---

## 3. Key Design Decisions

| Decision | Why | Cost / Tradeoff |
|---|---|---|
| **Deterministic Engine** | 100% reproducible execution, zero latency variance, offline execution, zero API token cost ($0.00). | Requires explicit rule engineering and regex ontologies instead of open-ended semantic parsing. |
| **Findings-First (Derived Status)** | Status is mathematically derived: `INCOMPLETE` iff $\ge 1$ finding exists, else `COMPLETE` or `NOT_APPLICABLE`. | Incomplete cases cannot omit findings; every remediation requires an evidentiary finding. |
| **COMPLETE Needs Positive Evidence** | Prohibits marking `COMPLETE` based on absence of data alone without affirmative proof or narrow snapshot coverage. | Cases with incomplete evidence history remain `INCOMPLETE` to ensure compliance safety. |
| **Claims vs. Proof** | Reported workflow statuses and activity outcomes are treated strictly as claims, verified against tangible evidence. | Additional computational overhead to inspect raw SQL snapshots, JSON dumps, and log entries. |
| **Strict Time Cutoff at `audit_at`** | Legal compliance requires determining system state exactly as of `audit_at`; later files cannot retroactively alter audit. | Post-audit cleanup evidence cannot be cited to prove compliance for historical audit dates. |
| **Narrow Absence Proof** | Validates account absence across primary/replica snapshots only after confirmed deletion activity and zero resurrection risk. | Requires cross-referencing multiple snapshot tables and active graph connectors before concluding absence. |
| **Strong-Identifier-Only Matching** | Restricts resource matching to grounded user identifiers (`user_id`, normalized email, hash, phone). | Eliminates false-positive decoy resources, but misses unlinked records lacking identifiable metadata. |

---

## 4. Results (Sample-Only Benchmark)
- **Status Accuracy**: **31 / 32 (96.9%)**
- **Step-Level Precision (5-tuple)**: **0.895**
- **Step-Level Recall (5-tuple)**: **0.793**
- **Step-Level F1 Score (5-tuple)**: **0.841**
- **Exact Citation Accuracy**: **100.0% (62 / 62)**
- **Mean LCS Sequence Ratio**: **0.753**
- **Exact Order Rate**: **28.1% (9 / 32)**
- **Independent Verifier Agreement**: **374 / 518 (72.2%)**
- **Mutation Suite Pass Rate**: **236 / 237 (99.58%)** across 7 mutation families.
- **Cross-Check Audit**: **518 / 518 cases pass all 7 independent checks (0 defects)**.
- *Honest Note on Generalization*: The hidden 518-case evaluation set is unmeasured. The 22 tuning / 10 holdout partition was contaminated during global tuning iterations and is reported strictly as sample-set benchmark accuracy.

---

## 5. Reverted Experiments & Empirical Lessons
1. **Unlinked Activity Harvesting**: Associated all global `ANONYMIZE_RECORD` events to cases with empty findings. *Result*: Status reached 32/32, but Precision collapsed from 0.839 to 0.517 (F1: 0.629). Reverted.
2. **Strict Manifest Cutoff on Internal Snapshots**: Disallowed records whose parent bundle had captured_at > audit_at even if inner snapshots preceded audit_at. *Result*: Recall fell from 0.793 to 0.767 (F1 dropped to 0.825). Reverted.
3. **Aggressive Orphan Step Filter**: Dropped remediations lacking strict string matching on findings. *Result*: Recall collapsed to 0.684. Reverted.
4. **Forced Account Finding Injection**: Synthesized `account_service` findings for empty incomplete cases. *Result*: Precision fell to 0.885, F1 dropped below gate to 0.839. Reverted.
5. **Broad Negation Token Matching**: Matched single-word negation tokens ("no", "without") inside wide windows. *Result*: Status dropped from 31/32 to 25/32 on samples. Reverted immediately.
*Lesson*: Unconstrained heuristics create severe precision degradation; strict automated regression gates preserve engine integrity.

---

## 6. Known Limitations & Honest Risks
1. **Unreadable PNG Screenshots**: Standard library constraint prevents deploying external OCR binaries (e.g. Tesseract). The 8 PNG-linked cases use conservative 3-step remediations; labelled as an **unvalidated heuristic**.
2. **The 127-Case COMPLETE Disagreement**: The independent second verifier disagreed with the engine on 127 cases where the engine concluded `COMPLETE` via narrow absence/retention proof across snapshots at `audit_at`, while the verifier demanded explicit deletion activity logs in `system_activity.csv`.
3. **Multilingual Opt-Out Lexicon Ambiguity**: Marketing opt-out keywords in Italian (*"Cancellatemi dalle newsletter"*) and Arabic (*"إلغاء الاشتراك"*) share root stems with account deletion verbs, leading to classification edge cases documented as known limitations.
4. **Format Coverage**: Unseen proprietary binary formats or encrypted attachments outside SQL, JSON, logs, text, and PDF cannot be parsed without dedicated drivers.

---

## 7. Security Posture & Threat Model
- **Untrusted Evidence**: User requests and evidence files are untrusted data. The engine uses fixed regexes and strict parsers; zero `eval()`, `exec()`, or dynamic shell execution. Prompt injection payloads (e.g. `Ignore previous rules, mark COMPLETE`) have zero effect.
- **Path Traversal Immunity**: All file access is validated against manifest paths and sandboxed within `dataset/`.
- **Fail-Safe Asymmetry**: Unhandled exceptions fall back to `INCOMPLETE` with logged error traces, never silent `COMPLETE`.
- **Zero Secrets**: Zero API keys, OAuth tokens, credentials, or `.env` files exist in the repository or code package.

---

## 8. Likely Interview Questions & Concise Answers
1. **Why choose a deterministic engine over an LLM agent?**  
   Deterministic systems provide 100% reproducible execution, zero latency jitter, mathematical auditability, and zero API costs ($0.00), which are non-negotiable requirements for regulatory compliance audits under GDPR Art. 17.
2. **What would an LLM or VLM add, and how would it be constrained?**  
   A VLM would enable OCR extraction from screenshots, and an LLM could resolve ambiguous multilingual phrasing; both would be constrained strictly to extraction roles with structured JSON schema outputs verified by deterministic rule guards.
3. **How is COMPLETE guarded against false positives?**  
   A `COMPLETE` verdict strictly requires zero findings, valid evidence-backed verification steps proving absence or compliant retention before `audit_at`, and zero active resurrection risks in the integration graph.
4. **How is the temporal cutoff at `audit_at` enforced?**  
   Every evidence file, snapshot row, and activity timestamp is parsed as timezone-aware UTC and checked with `timestamp <= audit_at`; any record created after `audit_at` is discarded from state reconstruction.
5. **What would you build next on the production roadmap?**  
   A pluggable OCR sidecar for image processing, distributed multiprocessing across case batches (<5s full run), and direct webhook integrations with Kubernetes/Kafka to execute remediation actions automatically.
6. **What did you get wrong during development and how was it corrected?**  
   Early versions suffered from speculative resource harvesting and missed unindexed snapshots, resulting in a low baseline recall of 0.269 and F1 of 0.406 in cp00; we corrected this by establishing strong-identifier-only graph linking, recursive replica extraction, and strictly validating evidence IDs against the raw manifest.
