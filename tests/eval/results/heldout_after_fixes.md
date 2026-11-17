# Held-Out Re-Evaluation After General Fixes *(Post-Fix — No Longer Blind)*

> **Important Methodological Note:** This report is **post-fix and no longer blind**. The frozen blind baseline remains preserved unchanged in [`heldout_report.md`](heldout_report.md). All 8 fixes implemented in Milestone 4 Step 2c were general AST/parser/detector improvements backed by independent unit tests with new minimal snippets.

---

## 1. Held-Out Metrics: Frozen Blind vs. Post-Fix

| Metric | Blind Held-Out (`heldout_report.md`) | Post-Fix Held-Out *(No Longer Blind)* | Delta |
| :--- | :---: | :---: | :---: |
| **Overall Precision** | 0.8500 (`17 TP, 3 FP`) | **1.0000** (`22 TP, 0 FP`) | **+0.1500** |
| **Overall Recall** | 0.7727 (`17 TP, 5 FN`) | **1.0000** (`22 TP, 0 FN`) | **+0.2273** |
| **Overall F1** | 0.8095 | **1.0000** | **+0.1905** |
| **Security Precision / Recall / F1** | `0.9091 / 0.6667 / 0.7692` | **`1.0000 / 1.0000 / 1.0000`** | `+0.0909 / +0.3333 / +0.2308` |
| **Code Quality Precision / Recall / F1** | `0.7778 / 1.0000 / 0.8750` | **`1.0000 / 1.0000 / 1.0000`** | `+0.2222 / 0.0000 / +0.1250` |
| **Clean Sample FPs (`clean_scheduler.py`)** | 1 FP (`Magic Number`) | **0 FPs** | **-1 FP** |
| **Clean Sample FPs (`CleanLedgerService.java`)** | 0 FPs | **0 FPs** | Maintained |
| **Severity Classification Accuracy** | 100.0% (`17 / 17`) | **100.0%** (`22 / 22`) | Maintained |
| **Severity Consistency (3 runs)** | 100.0% (`20 / 20`) | **100.0%** (`22 / 22`) | Maintained |
| **Remediation Specific / Pattern-Removed** | 80.0% (`16 / 20`) | **77.3%** (`17 / 22`) | 5 structural/untemplated items |
| **Remediation Syntax-Valid Rate** | 100.0% (`20 / 20`) | **95.5%** (`21 / 22`) | 1 newly detected Java TLS anonymous class |
| **Remediation Two-Tier Verified Rate** | 60.0% (`12 / 20`) | **68.2%** (`15 / 22`) | **+8.2 pp** |
| **PDF Report Completeness** | 100.0% (`6 / 6`) | **100.0%** (`6 / 6`) | Maintained |

---

## 2. Per-Sample Post-Fix Breakdown

| Sample | Language | Type | Expected | Detected | TP | FP | FN | Precision | Recall | F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `billing_worker.py` | Python | Vulnerable | 5 | 5 | 5 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `inventory_api.py` | Python | Vulnerable | 6 | 6 | 6 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `clean_scheduler.py` | Python | Clean | 0 | 0 | 0 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `PatientPortalController.java` | Java | Vulnerable | 5 | 5 | 5 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `TelemetryArchiveService.java` | Java | Vulnerable | 6 | 6 | 6 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `CleanLedgerService.java` | Java | Clean | 0 | 0 | 0 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

---

## 3. Development Eval Set Regression Check (`tests/samples/`)
Re-running the 7-sample development evaluation set confirmed **zero regressions**:
* **Overall Detection:** `P = 1.0000`, `R = 1.0000`, **`F1 = 1.0000`** (`49 TP, 0 FP, 0 FN`)
* **Remediation Quality:** `75.5%` specific & pattern-removed, `100.0%` syntax-valid, `69.4%` two-tier verified
* **RAG Relevance:** `100.0%` Hit@3, `80.0%` Precision@3, `100.0%` Assistant grounded citation rate, `100.0%` out-of-scope decline accuracy
* **PDF Completeness:** `7 / 7` (`100.0%`)

