# Optimization Log — Before vs. After Evaluation (Milestone 4, Step 2)

This document records the 5 weakest areas identified from the baseline evaluation across the 7 Milestone 4 samples (`py_small.py`, `py_medium.py`, `py_complex.py`, `py_clean.py`, `JavaSmall.java`, `JavaMedium.java`, `JavaComplex.java`), the targeted fixes applied, and the exact before/after metrics from re-running `tests/eval/run_eval.py`.

---

## Executive Before / After Summary

| Metric | Baseline (Before) | Optimized (After) | Delta |
| :--- | :---: | :---: | :---: |
| **Overall Detection Precision** | 0.8444 (38 TP, 7 FP) | **1.0000** (49 TP, 0 FP) | **+0.1556** |
| **Overall Detection Recall** | 0.7755 (38 TP, 11 FN) | **1.0000** (49 TP, 0 FN) | **+0.2245** |
| **Overall Detection F1** | 0.8085 | **1.0000** | **+0.1915** |
| **Security Detection Recall / F1** | 0.6207 / 0.7200 | **1.0000 / 1.0000** | **+0.3793 / +0.2800** |
| **Code Quality Precision / F1** | 0.8333 / 0.9091 | **1.0000 / 1.0000** | **+0.1667 / +0.0909** |
| **Clean Sample False Positives (`py_clean.py`)** | 0 | **0** | Maintained (0 FP) |
| **Severity Classification Accuracy** | 100.0% (38/38) | **100.0% (49/49)** | Maintained |
| **Severity Consistency (3 runs)** | 100.0% (sev & score) | **100.0% (sev & score)** | Maintained |
| **Remediation Specific Fix Rate** | 55.6% (25/45) | **75.5% (37/49)** | **+19.9 pp** |
| **Remediation Syntax-Valid Rate** | 97.8% (44/45) | **100.0% (49/49)** | **+2.2 pp** |
| **Remediation Vulnerable Pattern Removed** | 53.3% (24/45) | **75.5% (37/49)** | **+22.2 pp** |
| **Remediation Two-Tier Self-Verified Rate** | 22.2% (10/45) | **69.4% (34/49)** | **+47.2 pp** |
| **RAG Retriever Hit Rate@3** | 100.0% (20/20) | **100.0% (20/20)** | Maintained |
| **RAG Retriever Precision@3** | 71.7% | **80.0%** | **+8.3 pp** |
| **RAG Assistant Grounded Citation Rate** | 65.0% (13/20) | **100.0% (20/20)** | **+35.0 pp** |
| **RAG Expected-Source Citation Rate** | 55.0% (11/20) | **95.0% (19/20)** | **+40.0 pp** |
| **RAG Out-of-Scope Decline Accuracy** | 100.0% (3/3) | **100.0% (3/3)** | Maintained |
| **PDF Report Completeness** | 100.0% (7/7) | **100.0% (7/7)** | Maintained |

---

## Detailed Analysis of the 5 Weakest Areas & Targeted Optimizations

### 1. Security Detection Recall & Classification Gaps
- **Problem (Before):** Security Recall was **62.07%** (`18/29`, 11 False Negatives) and Security Precision was **85.71%** (3 False Positives):
  - All 3 Java SQL injection samples (`JavaSmall.java`, `JavaMedium.java`, `JavaComplex.java`) were missed because `detect_java_sqli` only inspected single-line `executeQuery("..." + var)` and missed preceding `String query = "SELECT ..." + var;` assignments.
  - Both Java XSS samples (`JavaMedium.java`, `JavaComplex.java`) were missed because `detect_java_xss` only matched `response.getWriter().write(...)` and ignored injected `PrintWriter writer` calls (`writer.write("<div..." + var)`).
  - Python path traversal (`py_medium.py`) was missed when `os.path.join(self.base_dir, request_filename)` was assigned to a local variable before `open()`.
  - Plaintext password equality checks (`CWE-287`, both Python and Java) and unprotected Java `@GetMapping("/admin/export")` endpoints (`CWE-862`) had no detectors.
  - Python `WTF_CSRF_ENABLED = False` was bundled under `CWE-209` instead of `CWE-352`, and Java `ObjectInputStream` emitted duplicate findings on consecutive lines (`new ObjectInputStream` + `ois.readObject()`).
- **Targeted Fix (`agents/security.py`):**
  - Extended `detect_java_sqli` with local concatenated SQL string tracking, extended `detect_java_xss` to `writer.write/print/println`, extended `detect_py_traversal` to propagate `os.path.join(...)` taint, deduplicated adjacent Java `ObjectInputStream` hits, split `SEC-PY-CSRF` (`CWE-352`), and added `SEC-PY-INSECURE-AUTH` (`CWE-287`), `SEC-JV-INSECURE-AUTH` (`CWE-287`), and `SEC-JV-BAC` (`CWE-862`) while preserving existing `SEC-PY-AUTH-CONFIG` (`CWE-209`) backward compatibility.
- **Result (After):** Security Recall rose **62.07% -> 100.00%** (`29/29`), Security Precision rose **85.71% -> 100.00%** (`0 FP`), Security F1 rose **0.7200 -> 1.0000**.

---

### 2. ChatAssistant Intent Routing & Uncited Fallback Drops
- **Problem (Before):** Although ChromaDB retrieval achieved **100.0% Hit@3**, `ChatAssistant` only produced grounded citations on **65.0% (13/20)** of in-scope questions (`expected_source_citation_rate = 55.0%`):
  - Three valid OWASP 2025 questions (`Q11` Supply Chain, `Q12` Insecure Design, `Q13` Authentication Failures) were misclassified as `out_of_scope` (`grounded=False`) despite cosine similarity scores of `0.66–0.75`, because `IN_SCOPE_DOMAIN_WORDS` lacked terms like `supply`, `design`, `threat`, `authentication`, and `session`.
  - Four general security/quality questions (`Q06` MD5/SHA-1, `Q08` Command Injection, `Q09` Path Traversal, `Q16` God Class) routed to `finding_explanation` / `fix_request`, failed to find a matching issue in `py_complex.py`, and returned an ungrounded `"specify a finding"` prompt instead of answering from retrieved KB chunks.
- **Targeted Fix (`agents/chat_assistant.py`):**
  - Expanded `IN_SCOPE_DOMAIN_WORDS` with complete OWASP Top 10:2025 and clean-code vocabulary.
  - Added a grounded fallback in `ChatAssistant.ask()`: when `finding_explanation` or `fix_request` has no explicit line/finding target (`resolved_finding is None` and `resolution_error is None`) and KB citations exist, route directly to `_answer_concept_or_practice()`.
- **Result (After):** Assistant Grounded Citation Rate rose **65.0% -> 100.0% (20/20)** and Expected-Source Citation Rate rose **55.0% -> 95.0% (19/20)** while maintaining **100.0% (3/3)** out-of-scope decline accuracy.

---

### 3. Remediation Specificity, Syntax Bug & False Verification Rejections
- **Problem (Before):** Specific Fix Rate was **55.6%** (`25/45`), Syntax-Valid Rate was **97.8%** (`44/45`, 1 syntax error on Python SQLi `+` concatenation in `py_complex.py`), Vulnerable Pattern Removed was **53.3%**, and Two-Tier Self-Verified Rate was only **22.2%** (`10/45`):
  - Python SQLi string-concatenation regex (`'...' + var + "'"`) left an unbalanced trailing quote, failing `ast.parse`.
  - `_verify_remediation()` falsely rejected valid fixes for HIGH-severity findings whenever the file already contained pre-existing CRITICAL findings (`if new_criticals and not orig_was_crit`), failing verification even when the target issue was cleanly eliminated.
  - Security categories including Path Traversal (`CWE-22`), Insecure TLS (`CWE-295`), CSRF (`CWE-352`), Insecure Auth (`CWE-287`), Broken Access Control (`CWE-862`), Python `render_template_string` XSS, and multiline Java SQLi lacked dedicated templates and fell back to generic `# Remediated:` comments.
  - Magic Number remediation hardcoded `42.5`/`888` instead of extracting the actual literal.
- **Targeted Fix (`agents/remediation_agent.py`):**
  - Fixed Python SQLi `+` concatenation quoting with `ast.parse` sanity check, added multiline Java SQLi support, added specific syntax-valid templates for `CWE-22`, `CWE-295`, `CWE-352`, `CWE-287`, `CWE-862`, `CWE-209`, Python/Java XSS, and dynamic magic number extraction.
  - Updated `_verify_remediation()` to compare post-patch critical counts against `baseline_critical_count` rather than assuming zero pre-existing criticals.
- **Result (After):** Syntax-Valid Rate reached **100.0% (49/49)**, Specific Fix & Pattern-Removed Rates rose **55.6% / 53.3% -> 75.5% (37/49)** (100% of all security & line-level smells; only structural refactorings like God Class / Long Method remain manual), and Two-Tier Self-Verified Rate jumped **22.2% -> 69.4% (34/49)**.

---

### 4. Code Quality False Positives (Sliding-Window Duplicates, Named Kwargs, `__init__` Count)
- **Problem (Before):** Code Quality Precision was **83.33%** (`20 TP, 4 FP`):
  - `_check_duplicate_code` emitted overlapping duplicate findings 7 lines apart for a single duplicated method (`py_complex.py` line 214, `JavaComplex.java` line 227).
  - `_py_check_magic_docstring_naming` flagged self-documenting keyword arguments like `timeout=5` (`py_complex.py` line 68) as Magic Numbers.
  - `_py_check_parameters_and_god_class` counted Python `__init__` toward `MAX_CLASS_METHODS`, inconsistently flagging `py_medium.py` (10 domain methods + `__init__`) as a God Class unlike Java constructors.
- **Targeted Fix (`agents/code_analysis.py`):**
  - Merged contiguous overlapping duplicate spans in `_check_duplicate_code`.
  - Excluded direct keyword-argument constants (`ast.keyword`) and local `UPPER_CASE` named constants from Magic Number alerts.
  - Excluded Python dunder lifecycle methods (`__init__`, etc.) from the God Class domain-method count.
- **Result (After):** Code Quality Precision rose **83.33% -> 100.00%** (`20 TP, 0 FP`) and Code Quality F1 rose **0.9091 -> 1.0000**, with all 21 existing `test_code_analysis.py` tests passing unchanged.

---

### 5. RAG Retrieval Ranking Precision (`Precision@3`)
- **Problem (Before):** Pure dense cosine search (`k=3`) achieved **71.7% Precision@3**, allowing high-chunk-count cheatsheets (especially `owasp_sqli_cheatsheet.txt`) to crowd out exact topic documents in ranks #2 and #3 (e.g., `Q03` Broken Access Control returned 2 SQLi cheatsheet chunks; `Q17` Code Smells returned `A05` and `A10` chunks).
- **Targeted Fix (`kb/retriever.py`):**
  - Implemented lightweight hybrid reranking (`_hybrid_rerank`) over-fetching `max(k*3, 10)` dense candidates and blending dense cosine similarity (`0.72`) with stop-word-filtered lexical overlap against chunk text and source filename (`0.28`).
- **Result (After):** Retriever `Precision@3` improved **71.7% -> 80.0%** (+8.3 pp), with `Hit Rate@3` maintained at **100.0% (20/20)** and zero regressions in `tests/test_retriever.py`.

---

## Milestone 4, Step 2c — General Fixes for Held-Out Limitations

Following the blind held-out validation recorded in [`heldout_report.md`](heldout_report.md) (`Overall F1 = 0.8095`, `5 FN`, `3 FP`), 8 general detector/quality fixes were implemented with independent unit tests (leaving `heldout_report.md` frozen and saving post-fix results to [`heldout_after_fixes.md`](heldout_after_fixes.md)):

| # | Limitation Fixed | General Code Change | Independent Unit Test |
| :---: | :--- | :--- | :--- |
| 1 | Unreachable `subprocess(..., shell=True)` branch | Merged `os` and `subprocess` checks under one `ast.Attribute` branch in `detect_py_cmdi` (`agents/security.py`) | `test_py_cmdi_subprocess_shell_true_reachable` |
| 2 | Missed `self.<secret> = "..."` & known tokens under arbitrary names | Added `ast.Attribute` target handling and name-independent `KNOWN_TOKEN_PATTERN` check in `detect_py_secrets` (`agents/security.py`) | `test_py_secrets_attribute_assignment_detected` |
| 3 | `"safeloader"` substring bug bypassing `yaml.UnsafeLoader` | Replaced substring check with exact AST loader name allowlist `{"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}` in `detect_py_deserial` (`agents/security.py`) | `test_py_deserial_yaml_unsafe_loader_vs_safe_loader` |
| 4 | Java `StringBuilder`/`StringBuffer` SQL injection missed | Added `.append(...)` chain & `.toString()` tracking in `detect_java_sqli` (`agents/security.py`) | `test_java_sqli_stringbuilder_chain_detected` |
| 5 | Custom Java anonymous `HostnameVerifier` / `X509TrustManager` TLS bypass missed | Added `HostnameVerifier` (`-> true` / `return true;`) and `X509TrustManager` checks in `detect_java_ssrf_tls` (`agents/security.py`) | `test_java_tls_anonymous_hostname_verifier_and_lambda` |
| 6 | False positive `Magic Number` on `secrets.token_hex(16)` | Exempted positional byte-length args to `secrets.token_*`, `os.urandom`, and `token_*` calls in `_py_check_magic_docstring_naming` (`agents/code_analysis.py`) | `test_magic_number_exempts_token_and_urandom_byte_lengths` |
| 7 | False positive Java CSRF hit inside Javadoc/comments | Added `_strip_java_comments()` (line-preserving) to `detect_java_auth_config`, `detect_java_sqli`, and `detect_java_ssrf_tls` (`agents/security.py`) | `test_java_csrf_ignores_comments_and_javadocs` |
| 8 | False positive `Missing Method Javadoc` on anonymous inner-class methods | Skipped `MethodDeclaration`s whose `javalang` ancestor path contains `ClassCreator` in `_java_check_methods_and_classes` (`agents/code_analysis.py`) | `test_java_missing_javadoc_skips_anonymous_inner_class_methods` |

* **Post-Fix Held-Out Re-Evaluation *(No Longer Blind)*:** Overall Precision `0.8500 -> 1.0000`, Recall `0.7727 -> 1.0000`, F1 `0.8095 -> 1.0000` (`22 TP, 0 FP, 0 FN`; `0` clean-sample FPs across Python & Java), while maintaining `F1 = 1.0000` (`49 TP, 0 FP, 0 FN`) on the 7-sample development eval set.

