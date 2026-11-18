# Live Demo Script (8–10 Minutes) — AI Code Review & Security Analysis Agent

## Pre-Demo Checklist (2 Minutes Before Presenting)
1. Activate the local virtual environment and start the Streamlit portal:
   ```powershell
   .\venv\Scripts\Activate.ps1
   streamlit run app/app.py
   ```
2. Open the local Streamlit URL (`http://localhost:8501`) in Chrome; verify the dark black-blue portal loads (the ChromaDB retriever warms automatically at startup using offline cached `all-MiniLM-L6-v2` weights).
3. Keep these three sample files ready to upload (or paste) from `tests/samples/`:
   - **Sample 1 (Simple — Python):** `tests/samples/py_small.py` (39 lines)
   - **Sample 2 (Moderate — Python):** `tests/samples/py_medium.py` (127 lines)
   - **Sample 3 (Complex — Java):** `tests/samples/JavaComplex.java` (281 lines)
4. Keep the pre-generated backup PDFs in `docs/demo_outputs/` (`review_py_small.pdf`, `review_py_medium.pdf`, `review_JavaComplex.pdf`) open in a PDF viewer tab in case of screen-sharing lag. *(Regenerate anytime via `python scripts/generate_demo_reports.py`.)*

---

## Minute-by-Minute Walkthrough (9 Minutes Total)

### 0:00 – 1:00 | Opening & Architecture Hook (1 min)
- **Say:** *"This is our AI Code Review & Security Analysis Agent for Python and Java. Instead of relying on a stochastic cloud LLM that can hallucinate findings or leak proprietary source code, we combine deterministic AST static analysis, a 22-rule OWASP Top 10:2025 security engine with taint tracking, self-verified automated remediation, a deterministic Code Health Score, an offline 113-chunk ChromaDB RAG assistant, and a 7-section ReportLab PDF report generator—all verified by 127 passing pytest tests."*
- Briefly point to the submission panel (language selector, Upload vs. Paste mode, quick sample buttons) and the 4-tab layout (`Overview`, `Findings`, `PR Summary`, `Ask the Assistant`).

---

### 1:00 – 3:00 | Sample 1 — Simple Python (`tests/samples/py_small.py`) (2 min)

#### What to Upload / Paste
- Select **Language:** `Python` → **Upload file:** `tests/samples/py_small.py` (39 lines, single-file account lookup helper) → click **Analyze Code**.

#### Expected Findings (Answer Key: `tests/samples/expected/py_small.json`)
- **Health Score:** **`73 / 100` (Grade `C`)** — `100 - 15 (CRITICAL) - 8 (HIGH) - 4 (MEDIUM) = 73`
- **Remediations:** **`3 / 3` two-tier verified (`100%`)**

| ID | Severity (Score) | Line(s) | Issue (Answer Key Match) | Agent |
| :--- | :---: | :---: | :--- | :--- |
| `SEC-001` | `CRITICAL` (`8.8`) | `26` | SQL Injection (`CWE-89`, `A05:2025`) — f-string query passed to `cursor.execute(query)` | Security |
| `SEC-002` | `HIGH` (`7.5`) | `13` | Hardcoded Secret (`CWE-798`, `A07:2025`) — fake AWS key fixture in `SERVICE_API_KEY` | Security |
| `CODE-001` | `MEDIUM` (`5.0`) | `37–38` | Overly Broad Exception Catch — `except Exception:` in `parse_positive_amount` | Code Analysis |

#### Live Portal Actions
- **Overview tab:** Show the `73/100 (Grade C)` SVG gauge, `3 of 3 fixes verified`, and the Executive Overview card.
- **Findings tab:** Expand `SEC-001` to show the Before/After parameterized query diff (`?` placeholders) and the green **Verified** badge (passed both `ast.parse` and SecurityAgent re-scan).
- **Ask the Assistant tab — 2 Questions to Ask:**
  1. `"Why is line 26 flagged and how do I fix it?"` → Demonstrates finding resolution by line number, parameterized SQL fix, and grounded citations to `A05_injection.md` / `owasp_sqli_cheatsheet.txt`.
  2. `"What are the best practices for storing API keys and secrets securely?"` → Demonstrates `best_practice` intent with KB citations to `owasp_secrets_cheatsheet.txt` / `A07_authentication_failures.md`.

#### What to Show in the PDF (`docs/demo_outputs/review_py_small.pdf` — 4 pages)
- Click **📕 Download PDF report** on the Findings or PR Summary tab (or open `review_py_small.pdf`):
  - **Page 1 (Cover):** Project title, `py_small.py`, Python, timestamp, `73/100 (Grade C)`.
  - **Page 2:** Executive Overview + Severity Breakdown table + embedded Matplotlib bar/pie chart.
  - **Pages 3–4:** Findings Summary Table, Detailed Findings with monospace Before/After patches, Prioritized Remediation Roadmap (`Fix Now` for `SEC-001`/`SEC-002`, `Next` for `CODE-001`), and Overall Code Quality Assessment.

---

### 3:00 – 5:30 | Sample 2 — Moderate Python (`tests/samples/py_medium.py`) (2.5 min)

#### What to Upload / Paste
- Select **Language:** `Python` → **Upload file:** `tests/samples/py_medium.py` (127 lines, `ReportPortalHelper` class mixing 5 OWASP vulnerabilities and 3 code smells) → click **Analyze Code**.

#### Expected Findings (Answer Key: `tests/samples/expected/py_medium.json`)
- **Health Score:** **`37 / 100` (Grade `F`)** — `100 - 30 (2 CRIT) - 24 (3 HIGH) - 8 (2 MED) - 1 (1 LOW) = 37`
- **Remediations:** **`6 / 8` two-tier verified** (all 5 security vulnerabilities + Magic Number verified; 2 structural smells intentionally flagged for manual refactoring)

| ID | Severity (Score) | Line(s) | Issue (Answer Key Match) | Agent |
| :--- | :---: | :---: | :--- | :--- |
| `SEC-001` | `CRITICAL` (`8.8`) | `25` | SQL Injection (`CWE-89`) in `search_reports` | Security |
| `SEC-002` | `CRITICAL` (`8.8`) | `30` | Command Injection (`CWE-78`) via `os.system("ping -c 1 " + request_host)` | Security |
| `SEC-005` | `HIGH` (`8.6`) | `45` | Path Traversal (`CWE-22`) via `os.path.join` + `open(target_path)` | Security |
| `SEC-003` | `HIGH` (`6.5`) | `36` | Cross-Site Scripting (`CWE-79`) via `render_template_string(f"...")` | Security |
| `SEC-004` | `HIGH` (`6.5`) | `40` | Weak Cryptography (`CWE-327`) via `hashlib.md5(...)` | Security |
| `CODE-001` | `MEDIUM` (`6.0`) | `48–67` | Deep Control Flow Nesting (depth 5 > threshold 4) in `evaluate_approval_matrix` | Code Analysis |
| `CODE-002` | `MEDIUM` (`5.0`) | `69–88` | Too Many Parameters (7 > threshold 5) in `build_notification_envelope` | Code Analysis |
| `CODE-003` | `LOW` (`2.0`) | `94` | Magic Number (`0.1375`) in `compute_shipping_fee` | Code Analysis |

#### Live Portal Actions
- **Findings tab:** Demonstrate **multi-criteria filtering** — filter Severity to `CRITICAL` + `HIGH` (shows 5 security issues), then toggle to `Code Analysis Agent` to isolate the 3 code smells; point out the **line-highlighted source code viewer** at the bottom.
- Highlight why `CODE-003` (`Magic Number 0.1375`) auto-extracts the exact literal into a named constant and verifies cleanly, whereas `Deep Control Flow Nesting` and `Too Many Parameters` honestly display `Manual Review` rather than faking a risky multi-block rewrite.
- **Ask the Assistant tab — 2 Questions to Ask:**
  1. `"What should I fix first?"` → Demonstrates `summary_request` intent, returning severity-and-effort prioritized order (`CRITICAL` SQLi/CMDi first).
  2. `"How do I prevent path traversal attacks when opening user-supplied filenames?"` → Demonstrates grounded KB retrieval citing `A01_broken_access_control.md` (`Path.resolve()` + containment check).
  - *(Optional 10-second bonus)* Ask `"What is the weather forecast in Tokyo tomorrow?"` to demonstrate the **out-of-scope guardrail** refusing off-topic questions.

#### What to Show in the PDF (`docs/demo_outputs/review_py_medium.pdf` — 7 pages)
- Show how the Severity Breakdown chart cleanly visualizes all four non-zero tiers (`2 CRITICAL`, `3 HIGH`, `2 MEDIUM`, `1 LOW`), how the Findings Summary Table lists all 8 items with OWASP/CWE context, and how the Remediation Roadmap separates `Fix Now` (5 Critical/High items), `Next` (2 Medium structural smells), and `Later` (1 Low magic number).

---

### 5:30 – 8:30 | Sample 3 — Complex Java (`tests/samples/JavaComplex.java`) (3 min)

#### What to Upload / Paste
- Select **Language:** `Java` → **Upload file:** `tests/samples/JavaComplex.java` (281 lines, multi-class commerce & Spring Security backend with 7 OWASP vulnerabilities and 6 code smells) → click **Analyze Code**.

#### Expected Findings (Answer Key: `tests/samples/expected/JavaComplex.json`)
- **Health Score:** **`21 / 100` (Grade `F`)** — showcases the **diminishing-returns cap** on `HIGH` findings: `6 HIGH × 8 = 48` is capped at **`32` pts**, so `100 - 30 (2 CRIT) - 32 (6 HIGH, capped) - 16 (4 MED) - 1 (1 LOW) = 21`!
- **Remediations:** **`7 / 13` two-tier verified**

| ID | Severity (Score) | Line(s) | Issue (Answer Key Match) | Agent |
| :--- | :---: | :---: | :--- | :--- |
| `SEC-001` | `CRITICAL` (`8.8`) | `47` | SQL Injection (`CWE-89`) in `findUserUnsafe` (multi-line `String query` + `executeQuery`) | Security |
| `SEC-004` | `CRITICAL` (`8.8`) | `57` | Insecure Deserialization (`CWE-502`) via `ObjectInputStream.readObject()` | Security |
| `SEC-006` | `HIGH` (`8.0`) | `32` | Insecure Authentication (`CWE-287`) — plaintext `password.equals(storedPassword)` | Security |
| `CODE-002` | `HIGH` (`8.0`) | `78–260` | God Class (`EnterpriseOrderService`: 12 methods > threshold 10) | Code Analysis |
| `SEC-003` | `HIGH` (`7.5`) | `23` | Hardcoded Secret (`CWE-798`) — `PAYMENT_API_SECRET` | Security |
| `SEC-005` | `HIGH` (`7.1`) | `27` | Broken Access Control — CSRF Disabled (`CWE-352`) via `http.csrf().disable()` | Security |
| `SEC-007` | `HIGH` (`7.0`) | `39` | Broken Access Control (`CWE-862`) — unprotected `@GetMapping("/admin/export")` | Security |
| `SEC-002` | `HIGH` (`6.5`) | `52` | Cross-Site Scripting (`CWE-79`) via `writer.write("<section..." + requestBio)` | Security |
| `CODE-003` | `MEDIUM` (`6.0`) | `111–132` | Deep Control Flow Nesting in `classifyOrderRisk` | Code Analysis |
| `CODE-004` | `MEDIUM` (`5.5`) | `136–200` | Long Method (65 lines > threshold 50) in `processFulfillmentPipeline` | Code Analysis |
| `CODE-001` | `MEDIUM` (`5.5`) | `221–226` | Duplicate Code Block (6+ lines matching lines 205–210) | Code Analysis |
| `CODE-005` | `MEDIUM` (`5.0`) | `105` | Overly Broad Catch Clause — `catch (Exception e)` in `safeParseCoupon` | Code Analysis |
| `CODE-006` | `LOW` (`2.0`) | `98` | Magic Number (`89.25`) in `computeLoyaltyDiscount` | Code Analysis |

#### Live Portal Actions
- **PR Summary tab:** Point out the **Penalty Deducted vs. Cap Limit** table showing `HIGH: 6 findings -> -32 pts (max 32 pts)`, the Prioritized Action Items ordered by Severity then Effort (e.g., Low-effort Hardcoded Secret and Insecure Auth ahead of High-effort God Class), and the one-click **Markdown / JSON / HTML / PDF** downloads.
- **Ask the Assistant tab — 2 Questions to Ask:**
  1. `"What are the risks of insecure deserialization using Java ObjectInputStream?"` → Cites `A08_software_or_data_integrity_failures.md` (`CWE-502` gadget chains → switch to typed JSON DTOs).
  2. `"How do I fix finding SEC-001?"` → Resolves `SEC-001` by exact ID and returns the Java `PreparedStatement` replacement with `A05_injection.md` / `owasp_sqli_cheatsheet.txt` citations.

#### What to Show in the PDF (`docs/demo_outputs/review_JavaComplex.pdf` — 13 pages)
- Scroll through the 13-page PDF to show clean automatic pagination, running page numbers + filename footers (`JavaComplex.java`), color-coded severity badges across all 13 findings (including Java `PreparedStatement`, `@PreAuthorize`, `BCrypt`, and CSRF fixes), wrapped monospace code snippets, and the Section 6 **Overall Code Quality Assessment** (Strengths, Weaknesses, and Health Score reasoning).

---

### 8:30 – 9:30 | Evaluation Rigor & Wrap-Up (1 min)
- **Say:** *"Rather than trusting our 1.0000 F1 on the 7 development files, we also ran a blind held-out validation on 6 completely unseen Python and Java files. That honest generalization test scored 0.8095 F1 with 100% severity accuracy and 100% 3-run consistency, and surfaced 8 specific edge cases—like `yaml.UnsafeLoader` and Java `StringBuilder` SQLi—which we then fixed generally with independent unit tests. Today all 127 tests pass."*

---

## Talking Points per Agent

- **Code Analysis Agent (`agents/code_analysis.py`):** Uses Python's native `ast` and Java's `javalang` to check 10+ maintainability rules against transparent, configurable thresholds (`MAX_COMPLEXITY=10`, `MAX_FUNCTION_LINES=50`, `MAX_NESTING_DEPTH=4`, `MAX_CLASS_METHODS=10`). Merging overlapping duplicate spans and excluding anonymous inner-class Javadocs keeps noise near zero.
- **Security Agent (`agents/security.py`):** Runs 22 modular rules (11 Python, 11 Java) mapped to OWASP Top 10:2025 and CWE IDs, combining intraprocedural taint tracking, Shannon entropy + known-token secret matching, line-preserving Java comment stripping, CVSS-style scoring, and cached ChromaDB evidence retrieval.
- **Orchestrator (`agents/orchestrator.py`):** Runs Code Analysis and Security in parallel via `ThreadPoolExecutor` (`30s` timeout), isolates failures per agent, deduplicates overlapping spans by keeping higher `(severity_score, confidence)`, and sequences Remediation and PR Summary deterministically.
- **Remediation Agent (`agents/remediation_agent.py`):** Applies language-specific templates and enforces a **two-tier self-verification gate**—Tier 1 syntax parsing on the full patched file plus Tier 2 detector re-scan confirming the target vulnerability disappears without introducing new `CRITICAL` findings.
- **PR Summary Agent (`agents/pr_summary_agent.py`):** Synthesizes the deterministic `0–100` Code Health Score (`A–F`) with diminishing-returns caps, ranks fixes by highest severity then lowest developer effort, and generates PR-ready Markdown with unified diffs.
- **Chat Assistant (`agents/chat_assistant.py`):** Uses a 6-class intent router, multi-strategy finding resolver (ID, index, line, title, chat history), and hybrid dense+lexical ChromaDB retrieval (`0.72 / 0.28`, `113` chunks) with a `0.25` grounding threshold and `100%` out-of-scope refusal.
- **PDF Report Generator (`app/report_generator.py`):** Produces a 7-section ReportLab + Matplotlib PDF hardened against zero findings, 100+ findings pagination, very long lines, XML/Unicode characters, and missing remediations.

---

## Likely Evaluator Questions & Short Answers

1. **Q: Why use deterministic AST rules and offline RAG instead of sending code straight to an LLM?**
   *A:* Pure LLMs vary across runs, hallucinate line numbers/citations, and raise data-privacy concerns. Our hybrid design gives `100.0%` 3-run severity/score consistency, sub-second analysis, zero API cost, and verifiable citations from our local 113-chunk OWASP ChromaDB store.
2. **Q: Isn't `F1 = 1.0000` on your 7 evaluation files a sign of overfitting?**
   *A:* Yes—that is exactly why we treated the 7-sample suite as a development set and ran a **blind held-out evaluation** on 6 brand-new files (`heldout_report.md`). Our honest primary generalization score is **`F1 = 0.8095`** (`P = 0.8500, R = 0.7727`), which uncovered 5 real detector gaps and 3 false positives that we subsequently fixed with general AST rules and independent tests.
3. **Q: Why did remediation syntax-valid drop from `100%` to `95.5%` after your Step 2c fixes?**
   *A:* Fixing the 5 blind false negatives brought 5 new real vulnerabilities into the remediation denominator while removing 3 trivially patched false positives. Two newly caught idioms (`yaml.UnsafeLoader` in Python and anonymous `HostnameVerifier` in Java) lacked dedicated templates yet, causing 1 syntax miss (`21/22 = 95.5%`) even as two-tier self-verification rose from `60.0%` to `68.2%`.
4. **Q: Why are there API keys/tokens inside `tests/samples/`?**
   *A:* Every token (`AKIAIOSFODNN7EXAMPLE*`, `sk_live_...`, `ghp_...`, `xoxb-...`) is a deliberately fabricated test fixture used to verify `CWE-798` hardcoded-secret detection. No live credentials or `.env` files exist in the repo.
5. **Q: How does the Code Health Score avoid collapsing to `0` on a file with many low-severity smells?**
   *A:* Each severity tier has a diminishing-returns cap (`CRITICAL: max 45`, `HIGH: max 32`, `MEDIUM: max 20`, `LOW: max 10`). Even 50 `LOW` magic-number notices can deduct at most 10 points, keeping the score anchored to actual security risk (as seen in `JavaComplex.java`, where 6 `HIGH` findings cap at `-32` instead of `-48`).
6. **Q: What happens if ChromaDB is unavailable or one agent crashes?**
   *A:* Both `SecurityAgent` and `RemediationAgent` catch retriever errors and degrade gracefully offline; the orchestrator isolates agent exceptions/timeouts in `run_status` so surviving agents still produce a complete report.
7. **Q: What are the biggest limitations today?**
   *A:* Taint tracking is intraprocedural (single-file), `javalang==0.13.0` is limited to Java 8 grammar (no Java 17+ `record`/text blocks), structural smells require manual refactoring, and `yaml.UnsafeLoader` / Java anonymous `HostnameVerifier` need dedicated remediation templates.
