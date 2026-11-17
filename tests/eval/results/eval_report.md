# End-to-End Evaluation Report (Milestone 4, Step 2)

- **Generated:** `2026-11-17T15:26:23.090095+00:00`
- **Samples Evaluated:** `7` (3 Python, 3 Java, 1 Clean baseline)

## 1. Detection Accuracy

| Segment | TP | FP | FN | Precision | Recall | F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Overall** | 49 | 0 | 0 | 1.0000 | 1.0000 | **1.0000** |
| Security | 29 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| Code Quality | 20 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

### Per-Sample Detection Breakdown

| Sample | Lang | Complexity | Expected | Detected | TP | FP | FN | Precision | Recall | F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `JavaComplex.java` | java | complex | 13 | 13 | 13 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `JavaMedium.java` | java | medium | 8 | 8 | 8 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `JavaSmall.java` | java | small | 3 | 3 | 3 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `py_clean.py` | python | clean | 0 | 0 | 0 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `py_complex.py` | python | complex | 14 | 14 | 14 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `py_medium.py` | python | medium | 8 | 8 | 8 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `py_small.py` | python | small | 3 | 3 | 3 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

### False Negatives & False Positives Summary

- Zero false positives and zero false negatives across all samples.

## 2. Severity Classification Accuracy

- **Exact Severity Match:** `49 / 49` (**100.0%**)

### Confusion Matrix (Rows = Expected, Columns = Predicted)

| Expected \ Predicted | CRITICAL | HIGH | MEDIUM | LOW | INFO |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **CRITICAL** | 10 | 0 | 0 | 0 | 0 |
| **HIGH** | 0 | 21 | 0 | 0 | 0 |
| **MEDIUM** | 0 | 0 | 14 | 0 | 0 |
| **LOW** | 0 | 0 | 0 | 4 | 0 |
| **INFO** | 0 | 0 | 0 | 0 | 0 |

## 3. Severity Consistency (3 Runs per Sample)

- **Same Severity Rate:** `49 / 49` (**100.0%**)
- **Same Severity Score Rate:** `49 / 49` (**100.0%**)

## 4. Remediation Quality

- **Total Detected Findings Evaluated:** `49`
- **Specific Fix Rate (non-generic):** `37 / 49` (**75.5%**)
- **Syntax-Valid Corrected Code Rate:** `49 / 49` (**100.0%**)
- **Vulnerable Pattern Removed Rate:** `37 / 49` (**75.5%**)
- **Two-Tier Self-Verified Rate:** `34 / 49` (**69.4%**)
- **Weak / Fallback Remediation Types:** Deep Control Flow Nesting (java): 2, Deep Control Flow Nesting (python): 2, God Class (Large Class Smell) (java): 1, Long Method (java): 1, Duplicate Code Block (java): 1, Too Many Parameters (java): 1, God Class (Large Class Smell) (python): 1, Long Function (python): 1, Duplicate Code Block (python): 1, Too Many Parameters (python): 1

## 5. RAG Retrieval Relevance

- **In-Scope Questions:** `20`
- **Retriever Hit Rate@1:** `19 / 20` (**95.0%**)
- **Retriever Hit Rate@3:** `20 / 20` (**100.0%**)
- **Retriever Precision@3:** (**80.0%**)
- **Assistant Grounded Citation Rate:** `20 / 20` (**100.0%**)
- **Out-of-Scope Decline Accuracy:** `3 / 3` (**100.0%**)

| QID | Topic | Hit@3 | Grounded | Top-3 Retrieved Sources |
| :--- | :--- | :---: | :---: | :--- |
| Q01 | SQL Injection | YES | YES | A05_injection.md, owasp_sqli_cheatsheet.txt, owasp_sqli_cheatsheet.txt |
| Q02 | Secrets Management | YES | YES | A04_cryptographic_failures.md, owasp_secrets_cheatsheet.txt, owasp_secrets_cheatsheet.txt |
| Q03 | Broken Access Control | YES | YES | A01_broken_access_control.md, A01_broken_access_control.md, owasp_sqli_cheatsheet.txt |
| Q04 | XSS | YES | YES | A05_injection.md, A05_injection.md, owasp_sqli_cheatsheet.txt |
| Q05 | CSRF | YES | YES | A01_broken_access_control.md, A07_authentication_failures.md, A02_security_misconfiguration.md |
| Q06 | Cryptographic Failures | YES | YES | A04_cryptographic_failures.md, A04_cryptographic_failures.md, A04_cryptographic_failures.md |
| Q07 | Insecure Deserialization | YES | YES | A08_software_or_data_integrity_failures.md, A08_software_or_data_integrity_failures.md, A08_software_or_data_integrity_failures.md |
| Q08 | Command Injection | YES | YES | A05_injection.md, A05_injection.md, A05_injection.md |
| Q09 | Path Traversal | YES | YES | A01_broken_access_control.md, A07_authentication_failures.md, A02_security_misconfiguration.md |
| Q10 | Security Misconfiguration | YES | YES | A02_security_misconfiguration.md, A02_security_misconfiguration.md, A09_security_logging_and_alerting_failures.md |
| Q11 | Supply Chain Failures | YES | YES | A03_software_supply_chain_failures.md, A03_software_supply_chain_failures.md, A06_insecure_design.md |
| Q12 | Insecure Design | YES | YES | A06_insecure_design.md, A06_insecure_design.md, A06_insecure_design.md |
| Q13 | Authentication Failures | YES | YES | A07_authentication_failures.md, A09_security_logging_and_alerting_failures.md, A07_authentication_failures.md |
| Q14 | Security Logging | YES | YES | A09_security_logging_and_alerting_failures.md, A09_security_logging_and_alerting_failures.md, A09_security_logging_and_alerting_failures.md |
| Q15 | Exception Handling | YES | YES | A10_mishandling_of_exceptional_conditions.md, A10_mishandling_of_exceptional_conditions.md, A10_mishandling_of_exceptional_conditions.md |
| Q16 | Clean Code / God Class | YES | YES | code_smells_and_clean_code.md, code_smells_and_clean_code.md, code_smells_and_clean_code.md |
| Q17 | Code Smells | YES | YES | code_smells_and_clean_code.md, A01_broken_access_control.md, A02_security_misconfiguration.md |
| Q18 | Java PreparedStatement | YES | YES | A05_injection.md, A05_injection.md, owasp_sqli_cheatsheet.txt |
| Q19 | Secret Rotation | YES | YES | owasp_secrets_cheatsheet.txt, owasp_secrets_cheatsheet.txt, A04_cryptographic_failures.md |
| Q20 | Remediation Follow-Up | YES | YES | owasp_sqli_cheatsheet.txt, A05_injection.md, owasp_sqli_cheatsheet.txt |

- **OOS01** (`What is the weather forecast in Tokyo tomorrow?`): intent=`out_of_scope`, grounded=`False`, declined=`True`
- **OOS02** (`How do I train a golden retriever puppy to sit?`): intent=`out_of_scope`, grounded=`False`, declined=`True`
- **OOS03** (`What is the average distance from Earth to Mars in kilometers?`): intent=`out_of_scope`, grounded=`False`, declined=`True`

## 6. PDF Report Completeness

- **Reports Passed:** `7 / 7` (**100.0%**)

| Sample | Pages | Valid PDF | All 7 Sections | Count Matches | Non-Empty | Chart Images | Pass |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `JavaComplex.java` | 13 | True | True | True | True | 1 | **PASS** |
| `JavaMedium.java` | 7 | True | True | True | True | 1 | **PASS** |
| `JavaSmall.java` | 4 | True | True | True | True | 1 | **PASS** |
| `py_clean.py` | 3 | True | True | True | True | 1 | **PASS** |
| `py_complex.py` | 13 | True | True | True | True | 1 | **PASS** |
| `py_medium.py` | 7 | True | True | True | True | 1 | **PASS** |
| `py_small.py` | 4 | True | True | True | True | 1 | **PASS** |
