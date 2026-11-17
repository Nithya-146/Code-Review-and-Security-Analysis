# Held-Out Validation Report (Milestone 4, Step 2b)

This report evaluates the frozen pipeline (no agent, detector, template, or retriever changes) against **6 unseen held-out samples** written fresh with distinct domains, coding styles, variable names, and vulnerability idioms (**4 vulnerable/mixed samples** totaling **22 planted issues** + **2 clean samples** with **0 planted issues**). All ground-truth keys in `tests/samples/heldout/expected/` were locked in **before** running the evaluation harness.

---

## 1. Held-Out Evaluation Summary

| Metric | Result | Notes |
| :--- | :---: | :--- |
| **Overall Precision** | **0.8500** (`17 TP, 3 FP`) | 1 security FP (Javadoc comment), 2 code-quality FPs |
| **Overall Recall** | **0.7727** (`17 TP, 5 FN`) | 100% quality recall; 66.7% security recall on unseen patterns |
| **Overall F1** | **0.8095** | Compared to `1.0000` on development eval set (realistic generalization gap) |
| **Security Precision / Recall / F1** | `0.9091 / 0.6667 / 0.7692` | `10 TP, 1 FP, 5 FN` |
| **Code Quality Precision / Recall / F1** | `0.7778 / 1.0000 / 0.8750` | `7 TP, 2 FP, 0 FN` |
| **Severity Classification Accuracy** | **100.0%** (`17 / 17`) | All matched findings received exact expected severity |
| **Severity Consistency (3 runs)** | **100.0%** (`20 / 20`) | Deterministic severity and numeric score across all 3 runs |
| **Remediation Specific Fix Rate** | **80.0%** (`16 / 20`) | Only structural/doc smells fell back to manual guidance |
| **Remediation Syntax-Valid Rate** | **100.0%** (`20 / 20`) | All Python (`ast.parse`) & Java (`javalang`) patches parsed cleanly |
| **Remediation Pattern-Removed Rate** | **80.0%** (`16 / 20`) | 100% of targeted line-level fixes removed the vulnerable pattern |
| **Remediation Two-Tier Verified Rate** | **60.0%** (`12 / 20`) | 12/20 passed full AST + detector re-scan verification |
| **Clean Sample FPs — Python (`clean_scheduler.py`)** | **1 FP** (0 Security, 1 Quality) | `Magic Number` on `secrets.token_hex(16)` |
| **Clean Sample FPs — Java (`CleanLedgerService.java`)** | **0 FPs** | Zero security and zero code-quality false positives |
| **PDF Report Completeness** | **100.0%** (`6 / 6`) | All 7 sections, matching counts, and charts verified |

---

## 2. Per-Sample Breakdown

| Sample | Language | Type | Expected | Detected | TP | FP | FN | Precision | Recall | F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `billing_worker.py` | Python | Vulnerable | 5 | 4 | 4 | 0 | 1 | 1.0000 | 0.8000 | 0.8889 |
| `inventory_api.py` | Python | Vulnerable | 6 | 4 | 4 | 0 | 2 | 1.0000 | 0.6667 | 0.8000 |
| `clean_scheduler.py` | Python | Clean | 0 | 1 | 0 | 1 | 0 | 0.0000 | — | — |
| `PatientPortalController.java` | Java | Vulnerable | 5 | 5 | 4 | 1 | 1 | 0.8000 | 0.8000 | 0.8000 |
| `TelemetryArchiveService.java` | Java | Vulnerable | 6 | 6 | 5 | 1 | 1 | 0.8333 | 0.8333 | 0.8333 |
| `CleanLedgerService.java` | Java | Clean | 0 | 0 | 0 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

---

## 3. Missed Findings (5 False Negatives) — Root Cause & Known Limitations

1. **`billing_worker.py` (Lines 43–45) — Missed `command_injection` (`CWE-78`):**
   * *Code:* `return subprocess.Popen(cmd, shell=True)`
   * *Why it failed:* In `agents/security.py` (`detect_py_cmdi`), Branch 1 matches `if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):` and checks `node.func.value.id == "os"` inside it, while Branch 3 uses an identical `elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):` for `subprocess`. Because Branch 1 always captures `subprocess.Popen`, Branch 3 is unreachable dead code.
   * *Known Limitation:* Python `subprocess.*(..., shell=True)` command injections are currently missed until Branch 1 and Branch 3 are consolidated.

2. **`inventory_api.py` (Lines 23–25) — Missed `hardcoded_secret` (`CWE-798`):**
   * *Code:* `self.registry_token = "ghp_9f8e7d6c5b4a3210fedcba9876543210abcd"`
   * *Why it failed:* `detect_py_secrets` checks only `ast.Name` assignment targets (`token = "..."`) and skips `ast.Attribute` targets (`self.registry_token = "..."`).
   * *Known Limitation:* Hardcoded credentials assigned to Python instance attributes (`self.<secret>`) are not currently flagged.

3. **`inventory_api.py` (Lines 27–29) — Missed `insecure_deserialization` (`CWE-502`):**
   * *Code:* `return yaml.load(raw_manifest, Loader=yaml.UnsafeLoader)`
   * *Why it failed:* `detect_py_deserial` checks `"safeloader" not in ast.dump(loader_kw).lower()`. Because `"safeloader"` is a literal substring of `"unsafeloader"`, `yaml.UnsafeLoader` bypassed the check.
   * *Known Limitation:* `yaml.load(..., Loader=yaml.UnsafeLoader)` is misclassified as safe due to naive substring matching on `"safeloader"`.

4. **`PatientPortalController.java` (Lines 31–34) — Missed `sql_injection` (`CWE-89`):**
   * *Code:* `StringBuilder sb = new StringBuilder("SELECT ..."); sb.append(mrnParam).append("'"); return conn.createStatement().executeQuery(sb.toString());`
   * *Why it failed:* `detect_java_sqli` tracks `+`-concatenated `String` variables and inline `+` arguments in `executeQuery(...)`, but does not perform data-flow tracking across `StringBuilder.append(...)` calls passed via `sb.toString()`.
   * *Known Limitation:* Java SQL queries assembled via `StringBuilder` / `StringBuffer` are not currently detected.

5. **`TelemetryArchiveService.java` (Lines 35–41) — Missed `insecure_tls` (`CWE-295`):**
   * *Code:* `HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() { public boolean verify(...) { return true; } });`
   * *Why it failed:* `detect_java_ssrf_tls` looks only for literal strings `"trustallcertificates"`, `"allow_all_hostname_verifier"`, and `"checkservertrusted"`, missing custom anonymous `HostnameVerifier` classes that unconditionally return `true`.
   * *Known Limitation:* Custom Java `HostnameVerifier` / lambda TLS bypasses are not covered by the current line-pattern matcher.

---

## 4. False Positives (3 FPs) — Root Cause & Known Limitations

1. **`clean_scheduler.py` (Line 43) — False Positive `Magic Number` (`code_analysis`):**
   * *Code:* `return secrets.token_hex(16)`
   * *Why it failed:* Positional integer `16` is not in `ALLOWED_MAGIC_NUMBERS` (`{0, 1, 2, -1, 100, 0.0, 1.0}`), and only keyword-argument literals (`timeout=5`) are exempted.
   * *Known Limitation:* Common byte/bit-length positional arguments to standard-library crypto calls (e.g., `token_hex(16)`, `urandom(32)`) trigger low-severity Magic Number notices.

2. **`PatientPortalController.java` (Line 17) — False Positive `Broken Access Control (CSRF Disabled)` (`CWE-352`):**
   * *Code:* `* - CSRF protection disabled via securityBuilder.csrf().disable()` *(inside class Javadoc comment)*
   * *Why it failed:* `detect_java_auth_config` performs raw line substring checks (`"csrf().disable()" in lower`) without ignoring comment lines (`//`, `/*`, `*`).
   * *Known Limitation:* Regex/line-based Java security rules can match vulnerability patterns mentioned inside comments or Javadocs.

3. **`TelemetryArchiveService.java` (Line 37) — False Positive `Missing Method Javadoc` (`code_analysis`):**
   * *Code:* `public boolean verify(String hostname, SSLSession session)` *(inside anonymous `new HostnameVerifier() { ... }`)*
   * *Why it failed:* The Java Javadoc check walks every `MethodDeclaration` node without skipping overridden methods declared inside anonymous inner classes.
   * *Known Limitation:* Methods inside Java anonymous inner classes trigger `Missing Method Javadoc` notices even when the enclosing method is documented.

---

## 5. Remediation Observations (Held-Out Set)

* **Specific & Pattern-Removed Rate:** `16 / 20` (**80.0%**); all 4 non-specific items were structural/documentation code smells (`Too Many Parameters` x2, `Deep Control Flow Nesting` x1, `Missing Method Javadoc` x1), which intentionally require manual refactoring.
* **Syntax-Valid Rate:** `20 / 20` (**100.0%**).
* **Two-Tier Self-Verified Rate:** `12 / 20` (**60.0%**). Four line-level fixes removed the vulnerable pattern cleanly in the snippet but did not pass full-file re-scan verification because template matching assumed canonical naming from the dev set (e.g., `billing_worker.py` assigned SQL to `stmt = ...` rather than `query = ...`, so patching line 38 alone left `stmt` on line 37).
* *Known Limitation:* Multi-line remediation templates currently anchor on common variable names (`query =`) and single-line `os.system` / `new File` idioms rather than arbitrary local variable names or `ProcessBuilder` shell invocations.

