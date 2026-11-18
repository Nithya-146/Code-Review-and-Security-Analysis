# AI Code Review & Security Analysis Agent: Design, Implementation, and Empirical Evaluation

## Abstract

Manual code review is labor-intensive, inconsistent across reviewers, and prone to missing subtle security vulnerabilities under delivery pressure, while purely generative Large Language Model (LLM) reviewers suffer from non-determinism, hallucinated citations, and privacy constraints. This report presents the design, four-milestone implementation, and empirical evaluation of the **AI Code Review & Security Analysis Agent**, a deterministic, offline-capable multi-agent system for **Python** and **Java** source code. The platform coordinates Abstract Syntax Tree (AST) quality analysis, a 22-rule OWASP Top 10:2025 / CWE security scanner with source-to-sink taint tracking and Shannon entropy secret detection, automated two-tier self-verified remediation, deterministic Code Health Score synthesis, a 4-tab Streamlit developer portal, a ReportLab/Matplotlib PDF report generator, and a Retrieval-Augmented Generation (RAG) conversational assistant backed by a 113-chunk local ChromaDB vector store (`all-MiniLM-L6-v2` with hybrid dense-lexical reranking).

To avoid optimistic bias from iterative tuning, system accuracy is reported across three distinct regimes: (1) an **unseen blind held-out validation set** (6 fresh files, 22 planted issues + 2 clean baselines) serving as the **primary generalization estimate**, which achieved **Precision = `0.8500`, Recall = `0.7727`, F1 = `0.8095`**, `100.0%` severity accuracy and 3-run consistency, `100.0%` remediation syntax validity, `80.0%` specific/pattern-removed remediation, and `1` clean-file false positive across Python and Java; (2) a **7-sample development evaluation set** (49 planted issues + 1 clean baseline), where five targeted optimizations raised overall F1 from `0.8085` to `1.0000`, two-tier remediation verification from `22.2%` to `69.4%`, RAG Precision@3 from `71.7%` to `80.0%`, and grounded chat citation rate from `65.0%` to `100.0%` (`Hit@3 = 100.0%`, out-of-scope refusal = `100.0%`); and (3) a **post-fix held-out re-evaluation** *(after fixing documented limitations, no longer blind)*, which raised held-out F1 to `1.0000` (`0` clean-sample FPs) and two-tier verified remediation to `68.2%` (`15/22`), while exposing a modest dip in remediation syntax validity (`100.0% -> 95.5%`) and pattern-removed rate (`80.0% -> 77.3%`) on newly caught untemplated vulnerability idioms. All `127` automated pytest tests pass.

---

## 1. Introduction and Problem Statement

Modern software teams ship code continuously across heterogeneous backends—frequently combining Python services for data/API workflows with Java services for enterprise business logic. In these environments, two recurring review bottlenecks emerge:

1. **Security Blind Spots:** High-impact vulnerabilities such as SQL Injection (`CWE-89`), OS Command Injection (`CWE-78`), Cross-Site Scripting (`CWE-79`), Hardcoded Credentials (`CWE-798`), Insecure Deserialization (`CWE-502`), Broken Access Control (`CWE-862`/`CWE-352`), and Insecure TLS (`CWE-295`) routinely slip past ad-hoc peer reviews when embedded in complex business logic.
2. **Maintainability Erosion & Reviewer Fatigue:** Code smells—God Classes, long methods, deep nesting, duplicate blocks, overly broad exception handlers, and unexplained magic numbers—obscure security flaws and increase defect density. Meanwhile, standalone Static Application Security Testing (SAST) tools output raw warnings without verified code fixes, pull-request prioritization, or interactive explanations grounded in authoritative security standards.

Pure LLM-based code reviewers address explanation and patching ergonomics, yet introduce non-deterministic severity ratings, inconsistent findings across repeated runs, cloud data-exfiltration risk, and fabricated security references. This project addresses these limitations through a **deterministic multi-agent architecture paired with local hybrid RAG**, uniting reproducible AST/rule analysis, self-verified patch templates, quantitative health scoring, executive PDF reporting, and citation-backed developer Q&A.

---

## 2. Project Objectives

The system was designed around six measurable engineering objectives:

1. **Dual-Language Static Inspection:** Parse and validate Python (`ast`) and Java (`javalang`) code deterministically, detecting OWASP Top 10:2025 vulnerabilities and clean-code smells.
2. **Parallel Multi-Agent Orchestration:** Execute Code Analysis and Security agents concurrently with fault isolation, per-agent timeout protection (`30.0s`), and span-based deduplication.
3. **Self-Verified Remediation:** Generate concrete replacement code for detected issues and verify patches via a two-tier gate (AST syntax check + detector regression re-scan).
4. **Grounded Conversational Assistance:** Build an offline ChromaDB RAG pipeline (`all-MiniLM-L6-v2`) with hybrid reranking that cites exact OWASP/Clean-Code sources and declines out-of-scope prompts.
5. **Actionable Portal & Executive Reporting:** Deliver an interactive 4-tab Streamlit UI and a 7-section ReportLab/Matplotlib PDF report generator resilient to edge cases (zero findings, `100+` findings, special characters, missing remediations).
6. **Rigorous, Non-Circular Evaluation:** Quantify detection, severity consistency, remediation quality, RAG relevance, and PDF completeness on both a development benchmark and an independent blind held-out set.

---

## 3. Standards Background

### 3.1 OWASP Top 10:2025 and MITRE CWE
Security findings are mapped directly to the **OWASP Top 10:2025** taxonomy encoded in `app/schemas.py` (`OWASPCategory`, `A01:2025` through `A10:2025`) and granular **MITRE Common Weakness Enumeration (CWE)** identifiers:
- **A01:2025 Broken Access Control:** Path Traversal (`CWE-22`), CSRF Disabled (`CWE-352`), Missing Authorization (`CWE-862`).
- **A02:2025 Security Misconfiguration:** Debug/Information Exposure (`CWE-209`), Improper Certificate/TLS Validation (`CWE-295`).
- **A04:2025 Cryptographic Failures:** Weak Hash/Cipher Algorithms (`CWE-327`, `CWE-328`, `CWE-330`).
- **A05:2025 Injection:** SQL Injection (`CWE-89`), OS Command Injection (`CWE-78`), Cross-Site Scripting (`CWE-79`).
- **A07:2025 Authentication Failures:** Hardcoded Credentials (`CWE-798`), Plaintext Password Comparison (`CWE-287`).
- **A08:2025 Software or Data Integrity Failures:** Insecure Deserialization (`CWE-502`).
- **A03, A06, A09, A10:2025:** Covered in the local RAG knowledge base (`kb/docs/`) for grounded developer education and exception-handling guidance.

### 3.2 CVSS v3.1-Style Scoring & Clean Code Principles
Security findings receive numeric scores (`0.0–10.0`) anchored to CWE CVSS v3.1 base benchmarks (`CWE_BASE_SCORES`), discounted by `1.0` point when source-to-sink taint flow is not confirmed. Quality analysis operationalizes Fowler's refactoring catalog and Martin's clean-code thresholds (cyclomatic complexity `<= 10`, function length `<= 50` lines, nesting depth `<= 4`, parameters `<= 5`, class methods `<= 10`, class size `<= 200` lines, duplicate blocks `>= 6` lines).

---

## 4. System Design

The platform follows a modular, schema-enforced pipeline defined by Pydantic v2 models (`app/schemas.py`):

1. **Intake & Syntax Pre-Validation:** `app/python_parser.py` and `app/java_parser.py` reject syntactically invalid submissions before analysis begins.
2. **Parallel Analysis Layer:** `agents/orchestrator.py` executes `CodeAnalysisAgent` and `SecurityAgent` concurrently inside a `ThreadPoolExecutor` (`timeout=30.0s`), isolating agent failures and recording per-agent runtimes and statuses.
3. **Merge, Deduplication & Prioritization:** `deduplicate_findings()` collapses overlapping same-type findings (retaining higher `(severity_score, confidence)`) and sorts deterministically by `(-severity_score, line_start, line_end)`.
4. **Remediation & Two-Tier Verification:** `RemediationAgent` applies language-specific patch templates (up to `50` findings), retrieves top-2 KB source references, validates patched-file syntax (Tier 1), and re-runs detectors to verify defect removal without adding new `CRITICAL` findings (Tier 2).
5. **PR Summary & Health Score Synthesis:** `PRSummaryAgent` computes a deterministic `0–100` Code Health Score (`A–F`) using diminishing-returns severity caps (`CRITICAL: 15 pts, cap 45`; `HIGH: 8 pts, cap 32`; `MEDIUM: 4 pts, cap 20`; `LOW: 1 pt, cap 10`; `INFO: 0`), orders fixes by severity then lowest developer effort, and generates a PR Markdown summary.
6. **Hybrid RAG & Conversational Assistant:** `kb/ingest.py` chunks 13 KB documents (`chunk_size=800`, `chunk_overlap=100`) into `113` cosine-indexed ChromaDB chunks embedded with `all-MiniLM-L6-v2`. `kb/retriever.py` over-fetches `max(k*3, 10)` dense candidates and reranks using `0.72 * dense + 0.28 * lexical_score`. `ChatAssistant` classifies user intent across 6 classes, resolves finding references (by ID, index, line, title, or history), enforces a `0.25` grounding threshold, and declines out-of-scope queries.
7. **Portal & PDF Reporting:** `app/app.py` and `app/ui_components.py` expose a 4-tab Streamlit UI (`Overview`, `Findings`, `PR Summary`, `Ask the Assistant`), while `app/report_generator.py` compiles a 7-section ReportLab PDF with an embedded Matplotlib severity chart.

---

## 5. Implementation per Milestone (Milestones 1–4)

| Milestone | Scope & Key Deliverables (Verified from Git History) | Test Suite Growth |
| :--- | :--- | :---: |
| **Milestone 1** | Python (`ast`) and Java (`javalang`) syntax pre-validation parsers (`app/python_parser.py`, `app/java_parser.py`), Pydantic schemas (`app/schemas.py`), 13-document OWASP Top 10:2025 & Clean Code KB (`kb/docs/`), idempotent ingestion (`kb/ingest.py`, `113` chunks), and local ChromaDB retriever (`kb/retriever.py`). | Foundation (`test_parsers`, `test_retriever`) |
| **Milestone 2** | `BaseAgent`, `CodeAnalysisAgent`, `SecurityAgent` (taint tracking, Shannon entropy, CVSS scoring, cached RAG evidence), parallel `Orchestrator`, Markdown/HTML report helpers (`app/report.py`), Streamlit dark-blue UI, and 10-sample planted benchmark (`tests/evaluate.py`, `26 TP / 0 FP / 0 FN`, `F1 = 1.000`). | Core detection & orchestration tests |
| **Milestone 3** | `RemediationAgent` with two-tier self-verification, `PRSummaryAgent` with capped Code Health Score (`85` tests passing); `ChatAssistant` RAG conversational agent (`100` tests passing); `app/ui_components.py` and 4-tab Streamlit portal with SVG gauges/donuts, filters, diffs, and AppTest smoke tests (`108` tests passing). | `85 -> 100 -> 108` tests passing |
| **Milestone 4** | **Step 1:** 7-section ReportLab/Matplotlib PDF generator (`app/report_generator.py`), Streamlit download buttons, 6 PDF edge-case tests (`114` tests). **Step 2:** 7-sample dev eval set, automated harness (`tests/eval/run_eval.py`), 5 targeted optimizations (`optimization_log.md`), 5 regression tests (`119` tests). **Step 2b:** 6-sample blind held-out validation (`heldout_report.md`). **Step 2c:** 8 general fixes + 8 new unit tests (`127` tests), post-fix re-evaluation (`heldout_after_fixes.md`). **Step 3:** Technical docs, academic report, demo script, demo PDFs, and criteria mapping. | `114 -> 119 -> 127` tests passing |

---

## 6. Testing and Evaluation Methodology

System verification combines four complementary layers:

1. **Automated Unit, Integration & Smoke Testing (`pytest`):** `127` automated tests across 11 modules covering parsers (`4`), retriever (`5`), code analysis (`23`), security detectors (`31`), orchestrator (`5`), remediation & PR summary (`15`), chat assistant (`15`), legacy report (`10`), UI components & Streamlit `AppTest` (`8`), PDF generator (`6`), and eval threshold regressions (`5`).
2. **Development Evaluation Suite (`tests/eval/run_eval.py`):** Evaluates 7 samples (`py_small.py`, `py_medium.py`, `py_complex.py`, `py_clean.py`, `JavaSmall.java`, `JavaMedium.java`, `JavaComplex.java`; `49` planted issues + `1` clean baseline) across 6 dimensions:
   - *Detection Accuracy:* Precision, Recall, and F1 overall and split by Security vs. Code Quality (matching by normalized issue type + line-range tolerance).
   - *Severity Classification Accuracy:* Exact severity match rate and `5x5` confusion matrix.
   - *Severity Consistency:* 3 repeated full-pipeline runs per sample verifying identical severity tier and numeric score.
   - *Remediation Quality:* Specific (non-generic) fix rate, corrected-code syntax validity (`ast.parse` / `javalang`), vulnerable-pattern removal rate, and two-tier self-verification rate.
   - *RAG Retrieval Relevance:* 20 in-scope security/clean-code questions (`Hit@1`, `Hit@3`, `Precision@3`, assistant grounded citation rate, expected-source citation rate) plus 3 out-of-scope questions (refusal accuracy).
   - *PDF Report Completeness:* Valid `%PDF` header, all 7 sections present, matching finding counts, non-empty sections, and embedded Matplotlib chart verification.
3. **Blind Held-Out Generalization Test (`tests/samples/heldout/`):** To measure generalization and guard against overfitting to the development samples, 6 brand-new samples (`billing_worker.py`, `inventory_api.py`, `clean_scheduler.py`, `PatientPortalController.java`, `TelemetryArchiveService.java`, `CleanLedgerService.java`; `22` planted issues + `2` clean baselines) were authored with distinct domains, variable names, and idioms, with ground-truth keys locked *before* running the frozen pipeline.
4. **Post-Fix Re-Evaluation *(No Longer Blind)*:** After documenting all 5 blind false negatives and 3 blind false positives in `heldout_report.md`, 8 general AST/detector fixes were implemented with independent minimal unit tests and re-evaluated on both sets while keeping `heldout_report.md` frozen.

---

## 7. Empirical Results

### 7.1 Primary Generalization Estimate — Blind Held-Out Validation (`heldout_report.md`)

Evaluated on the frozen pipeline with **zero code modifications** against 6 unseen files (`22` planted issues + `2` clean files):

| Evaluation Dimension | Blind Held-Out Result (Primary Generalization Estimate) | Breakdown / Notes |
| :--- | :---: | :--- |
| **Overall Precision / Recall / F1** | **`0.8500` / `0.7727` / `0.8095`** | `17 TP, 3 FP, 5 FN` |
| **Security Precision / Recall / F1** | `0.9091` / `0.6667` / `0.7692` | `10 TP, 1 FP, 5 FN` |
| **Code Quality Precision / Recall / F1** | `0.7778` / `1.0000` / `0.8750` | `7 TP, 2 FP, 0 FN` |
| **Clean Sample FPs (Python / Java)** | `1` FP (`clean_scheduler.py`) / `0` FPs (`CleanLedgerService.java`) | `Magic Number` on `secrets.token_hex(16)` |
| **Severity Classification Accuracy** | **`100.0%`** (`17 / 17`) | Zero severity misclassifications |
| **Severity Consistency (3 runs)** | **`100.0%`** (`20 / 20`) | Identical severity and numeric score across 3 runs |
| **Remediation Specific / Pattern-Removed** | **`80.0%`** (`16 / 20`) | 4 structural/doc smells fell back to manual guidance |
| **Remediation Syntax-Valid Rate** | **`100.0%`** (`20 / 20`) | All patches parsed cleanly (`ast.parse` / `javalang`) |
| **Remediation Two-Tier Verified Rate** | **`60.0%`** (`12 / 20`) | 4 line-level fixes missed full-file re-scan due to variable naming |
| **PDF Report Completeness** | **`100.0%`** (`6 / 6`) | All 7 sections, matching counts, and charts verified |

#### Blind Held-Out Per-Sample Results

| Sample | Language | Type | Expected | Detected | TP | FP | FN | Precision | Recall | F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `billing_worker.py` | Python | Vulnerable | 5 | 4 | 4 | 0 | 1 | 1.0000 | 0.8000 | 0.8889 |
| `inventory_api.py` | Python | Vulnerable | 6 | 4 | 4 | 0 | 2 | 1.0000 | 0.6667 | 0.8000 |
| `clean_scheduler.py` | Python | Clean | 0 | 1 | 0 | 1 | 0 | 0.0000 | — | — |
| `PatientPortalController.java` | Java | Vulnerable | 5 | 5 | 4 | 1 | 1 | 0.8000 | 0.8000 | 0.8000 |
| `TelemetryArchiveService.java` | Java | Vulnerable | 6 | 6 | 5 | 1 | 1 | 0.8333 | 0.8333 | 0.8333 |
| `CleanLedgerService.java` | Java | Clean | 0 | 0 | 0 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

---

### 7.2 Development Evaluation Result — Before vs. After Optimization (`eval_report.md`, `optimization_log.md`)

Evaluated across the 7 Milestone 4 development samples (`49` planted issues + `py_clean.py`), 20 in-scope RAG questions, 3 out-of-scope questions, and 7 PDFs:

| Metric | Dev Baseline (Before) | Dev Optimized (After) | Delta |
| :--- | :---: | :---: | :---: |
| **Overall Precision / Recall / F1** | `0.8444` / `0.7755` / `0.8085` | **`1.0000` / `1.0000` / `1.0000`** | `+0.1556` / `+0.2245` / **`+0.1915`** |
| **Security Recall / F1** | `0.6207` / `0.7200` | **`1.0000` / `1.0000`** | `+0.3793` / `+0.2800` |
| **Code Quality Precision / F1** | `0.8333` / `0.9091` | **`1.0000` / `1.0000`** | `+0.1667` / `+0.0909` |
| **Clean Sample FPs (`py_clean.py`)** | `0` | **`0`** | Maintained |
| **Severity Accuracy & 3-Run Consistency** | `100.0%` (`38/38`) / `100.0%` | **`100.0%` (`49/49`) / `100.0%`** | Maintained |
| **Remediation Specific Fix Rate** | `55.6%` (`25/45`) | **`75.5%` (`37/49`)** | `+19.9 pp` |
| **Remediation Syntax-Valid Rate** | `97.8%` (`44/45`) | **`100.0%` (`49/49`)** | `+2.2 pp` |
| **Remediation Pattern-Removed Rate** | `53.3%` (`24/45`) | **`75.5%` (`37/49`)** | `+22.2 pp` |
| **Remediation Two-Tier Verified Rate** | `22.2%` (`10/45`) | **`69.4%` (`34/49`)** | **`+47.2 pp`** |
| **RAG Hit@1 / Hit@3 / Precision@3** | — / `100.0%` / `71.7%` | **`95.0%` / `100.0%` / `80.0%`** | `+8.3 pp` P@3 |
| **RAG Assistant Grounded Citation Rate** | `65.0%` (`13/20`) | **`100.0%` (`20/20`)** | **`+35.0 pp`** |
| **RAG Expected-Source Citation Rate** | `55.0%` (`11/20`) | **`95.0%` (`19/20`)** | **`+40.0 pp`** |
| **RAG Out-of-Scope Decline Accuracy** | `100.0%` (`3/3`) | **`100.0%` (`3/3`)** | Maintained |
| **PDF Report Completeness** | `100.0%` (`7/7`) | **`100.0%` (`7/7`)** | Maintained |

*(The Milestone 2 planted benchmark in `docs/milestone2_results.md` independently achieved `26 TP / 0 FP / 0 FN`, `F1 = 1.000`, with zero false positives on `tricky_safe.py`, `clean_module.py`, `TrickySafe.java`, and `CleanService.java`.)*

---

### 7.3 Held-Out Re-Evaluation — After Fixing Documented Limitations, No Longer Blind (`heldout_after_fixes.md`)

> **Methodological Label:** The numbers in the right-hand column below are **after fixing documented limitations, no longer blind**, and must not be conflated with the blind generalization baseline in Section 7.1.

| Metric | Blind Held-Out (`heldout_report.md`) | Post-Fix Held-Out *(after fixing documented limitations, no longer blind)* | Delta |
| :--- | :---: | :---: | :---: |
| **Overall Precision / Recall / F1** | `0.8500` / `0.7727` / `0.8095` (`17 TP, 3 FP, 5 FN`) | **`1.0000` / `1.0000` / `1.0000`** (`22 TP, 0 FP, 0 FN`) | `+0.1500` / `+0.2273` / `+0.1905` |
| **Security P / R / F1** | `0.9091` / `0.6667` / `0.7692` | **`1.0000` / `1.0000` / `1.0000`** | `+0.0909` / `+0.3333` / `+0.2308` |
| **Code Quality P / R / F1** | `0.7778` / `1.0000` / `0.8750` | **`1.0000` / `1.0000` / `1.0000`** | `+0.2222` / `0.0000` / `+0.1250` |
| **Clean Sample FPs (Python / Java)** | `1` / `0` | **`0` / `0`** | `-1 FP` |
| **Severity Accuracy & 3-Run Consistency** | `100.0%` (`17/17`) / `100.0%` (`20/20`) | **`100.0%` (`22/22`) / `100.0%` (`22/22`)** | Maintained |
| **Remediation Specific / Pattern-Removed** | `80.0%` (`16/20`) | **`77.3%` (`17/22`)** | `-2.7 pp` *(see Section 8.2)* |
| **Remediation Syntax-Valid Rate** | `100.0%` (`20/20`) | **`95.5%` (`21/22`)** | `-4.5 pp` *(see Section 8.2)* |
| **Remediation Two-Tier Verified Rate** | `60.0%` (`12/20`) | **`68.2%` (`15/22`)** | **`+8.2 pp`** |
| **PDF Report Completeness** | `100.0%` (`6/6`) | **`100.0%` (`6/6`)** | Maintained |

Re-running the 7-sample development eval set after Step 2c confirmed **zero regressions** (`F1 = 1.0000`, `49 TP, 0 FP, 0 FN`).

---

## 8. Discussion and Honest Limitations

### 8.1 Overfitting Risk and the Value of Blind Held-Out Validation
Achieving `F1 = 1.0000` on a 7-sample development suite after iterative rule tuning is an expected upper bound, not an unbiased measure of real-world performance. Evaluating the frozen pipeline on 6 fresh held-out files immediately revealed a **`0.1905` F1 generalization gap** (`1.0000` dev vs. `0.8095` blind held-out) driven by real engineering bugs that development samples never exercised:
- An unreachable `elif` branch in `detect_py_cmdi` that silently dropped all `subprocess.*(..., shell=True)` calls.
- A naive substring check (`"safeloader" not in ...`) that misclassified `yaml.UnsafeLoader` as safe because `"safeloader"` is a literal substring of `"unsafeloader"`.
- Missing support for Python instance-attribute secrets (`self.registry_token = ...`), Java `StringBuilder` SQL assembly, and anonymous Java `HostnameVerifier` classes.
- Unstripped Java comments triggering a false positive CSRF warning inside Javadoc, `Magic Number` alerts on `secrets.token_hex(16)`, and Javadoc notices on anonymous inner-class methods.

This demonstrates why blind held-out evaluation is essential for static analysis agents: it exposed genuine defect classes rather than cosmetic formatting quirks, and allowed general fixes verified by independent unit tests.

### 8.2 Why Remediation Syntax-Valid and Pattern-Removed Rates Dipped After Step 2c
An instructive trade-off emerged between detection recall and remediation coverage in the post-fix held-out run (`heldout_after_fixes.md`):
- **Specific & Pattern-Removed Rate:** shifted from `80.0% (16/20)` to `77.3% (17/22)` (`-2.7 pp`), even though the absolute count of specific fixes increased from `16` to `17` and two-tier self-verified patches improved from `60.0% (12/20)` to `68.2% (15/22)` (`+8.2 pp`).
- **Syntax-Valid Rate:** shifted from `100.0% (20/20)` to `95.5% (21/22)` (`-4.5 pp`).

The cause is compositional rather than a regression in existing templates: Step 2c eliminated 3 false positives (which had been trivially patched) and introduced **5 newly detected real security findings** into the remediation denominator (`20 -> 22`). While `RemediationAgent` handled 3 of the 5 newly caught findings cleanly, **2 newly detected idioms lacked dedicated replacement templates**:
1. **`SEC-003` (`CWE-502`, Python `yaml.load(..., Loader=yaml.UnsafeLoader)` in `inventory_api.py`):** did not produce a syntax-valid corrected snippet (`has_corrected_code=false, syntax_valid=false`), accounting for the sole `1/22` syntax failure.
2. **`SEC-004` (`CWE-295`, Java anonymous `HostnameVerifier` in `TelemetryArchiveService.java`):** parsed syntactically (`syntax_valid=true`) but fell back to non-specific manual guidance (`specific=false, pattern_removed=false`).

Coupling detector expansion with corresponding remediation-template tests is therefore a direct priority for the next iteration.

### 8.3 Additional Architectural Constraints
- **Intraprocedural Scope:** Taint tracking operates per file without inter-module call-graph or framework dependency-injection tracing.
- **Java Grammar Coverage:** `javalang==0.13.0` reliably parses Java 8 constructs; modern Java 17–21 syntax (`record`, pattern matching `switch`, text blocks) requires migrating to a modern parser such as Tree-sitter.
- **Deterministic Offline Chat vs. Generative Fluency:** Rule-based intent routing and extractive KB composition guarantee `100.0%` out-of-scope refusal and verifiable citations without API keys, at the cost of less conversational flexibility on ambiguous multi-hop questions.
- **Structural Refactorings:** Architectural smells (`God Class`, `Long Method`, `Deep Control Flow Nesting`, `Duplicate Code Block`, `Too Many Parameters`) intentionally produce advisory guidance rather than automated multi-block rewrites.

---

## 9. Conclusion and Future Work

This project delivered a complete, offline-capable multi-agent code review and security analysis platform spanning Python and Java static analysis, 22 OWASP Top 10:2025 security rules, two-tier self-verified remediation, deterministic Code Health Scoring, a hybrid-reranked 113-chunk ChromaDB RAG assistant, a 4-tab Streamlit developer portal, and a 7-section ReportLab/Matplotlib PDF report generator—backed by `127` passing pytest tests. Blind held-out testing confirmed realistic generalization (`F1 = 0.8095`, `100%` severity accuracy & consistency, `100%` PDF completeness) while surfacing concrete detector and remediation template gaps that guided systematic engineering improvements.

### Planned Future Work
1. **Expand Remediation Templates:** Add targeted syntax-verified templates for `yaml.UnsafeLoader` (`yaml.safe_load`), Java anonymous `HostnameVerifier` / `X509TrustManager` removal, and arbitrary SQL local variable names.
2. **Modern Multi-Language AST Backend:** Replace `javalang` with Tree-sitter grammars to support Java 17/21 alongside TypeScript and Go.
3. **Interprocedural & Repository-Level Scanning:** Extend taint tracking across module imports and integrate as an automated GitHub Actions pull-request check.
4. **Optional Hybrid LLM Synthesis:** Support an opt-in local or enterprise LLM synthesis pass gated strictly behind the existing deterministic AST findings and ChromaDB grounding guard.

---

## 10. References

1. OWASP Foundation, *OWASP Top 10:2025 — Standard Awareness Document for Developers and Web Application Security* (local reference corpus in `kb/docs/A01`–`A10`).
2. OWASP Foundation, *OWASP Cheat Sheet Series: SQL Injection Prevention & Secrets Management* (`kb/docs/owasp_sqli_cheatsheet.txt`, `kb/docs/owasp_secrets_cheatsheet.txt`).
3. MITRE Corporation, *Common Weakness Enumeration (CWE)* — CWE-22, CWE-78, CWE-79, CWE-89, CWE-209, CWE-287, CWE-295, CWE-327, CWE-352, CWE-502, CWE-798, CWE-862.
4. FIRST.org, *Common Vulnerability Scoring System (CVSS) Version 3.1 Specification*.
5. M. Fowler, *Refactoring: Improving the Design of Existing Code*, 2nd ed., Addison-Wesley, 2018.
6. R. C. Martin, *Clean Code: A Handbook of Agile Software Craftsmanship*, Prentice Hall, 2008.
7. N. Reimers and I. Gurevych, "Sentence-BERT: Sentence Embeddings using Siamese BERT-Networks," *EMNLP-IJCNLP*, 2019 (`sentence-transformers/all-MiniLM-L6-v2`).
8. ChromaDB (`chromadb==1.5.9`), ReportLab (`reportlab==5.1.0`), Matplotlib (`matplotlib==3.11.2`), Streamlit (`streamlit==1.65.0`), Python `ast` standard library, and `javalang==0.13.0`.
