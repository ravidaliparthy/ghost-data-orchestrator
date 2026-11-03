# Usage Report: Ghost Data Still Exists Deletion-Audit Agent

**Challenge**: HackerRank Orchestrate (October 2026) — Ghost Data Still Exists  
**Generated At**: 2026-10-25 17:29:21  
**Evaluation Scope**: Full evaluation dataset (`dataset/deletion_requests.csv`, 518 cases)  

---

## 1. Runtime Model Usage Summary (Final Full-Dataset Run)

The final submission solution is **100% deterministic, rule-based, and stdlib-only**. It makes **zero** model API calls, invokes **zero** external LLMs or VLMs, and runs entirely offline on local compute.

| Metric | Metric Value |
|---|---|
| **Model Providers** | None (0 providers) |
| **Model Names** | None (Deterministic expert system) |
| **Model API Calls** | 0 |
| **Input Tokens** | 0 |
| **Output Tokens** | 0 |
| **Total Tokens** | 0 |
| **Average Tokens per Request** | 0.0 |
| **Estimated Total Cost** | **$0.00** |
| **Estimated Cost per Request** | **$0.00** |

---

## 2. Development Environment & Assistant Disclosure

During the interactive development, debugging, and verification of the system:
- **Coding Harness**: Antigravity IDE / Cline
- **Runtime Model**: Gemini 3.8 Flash / Claude 3.7 Sonnet (as recorded in `log.txt`)
- **Submission Runtime**: Standard Python 3.9+ runtime executing `code/main.py`
- **External Dependencies**: Zero (Python standard library only: `csv`, `json`, `re`, `sqlite3`, `hashlib`, `datetime`, `shutil`, `zlib`)
- **Total Solution Runtime**: ~35 seconds across all 518 cases (average ~0.06s per case)
