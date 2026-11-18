# Technical Documentation — AI Code Review & Security Analysis Agent

## 1. System Overview and Goals

The **AI Code Review & Security Analysis Agent** is a multi-agent static analysis, automated remediation, and RAG-grounded conversational code review system supporting **Python** and **Java** source files. It combines deterministic Abstract Syntax Tree (AST) inspection with a local ChromaDB vector knowledge base (OWASP Top 10:2025 and Clean Code standards) so that every analysis run is fast, reproducible, offline-capable, and free of LLM hallucinations on clean code.

### Primary Engineering Goals
1. **Deterministic Security & Quality Detection:** Identify OWASP Top 10:2025 vulnerabilities (mapped to CWE IDs) and maintainability code smells across Python (`ast`) and Java (`javalang`) with deterministic severity scoring.
2. **Parallel, Fault-Isolated Multi-Agent Execution:** Run quality and security analyses concurrently under per-agent timeouts (`30.0s`) and deduplicate overlapping spans before downstream synthesis.
3. **Self-Verified Automated Remediation:** Generate targeted Python/Java patches paired with two-tier verification (AST syntax parsing + detector regression re-scan).
4. **Actionable Developer & Executive Reporting:** Produce a deterministic `0–100` Code Health Score (`A`–`F`), Pull-Request-ready Markdown summary, interactive 4-tab Streamlit developer portal, and publication-ready multi-page PDF report.
5. **Grounded Conversational Assistance:** Allow developers to interrogate findings, fixes, and OWASP concepts via a Retrieval-Augmented Generation (RAG) assistant that cites local knowledge base chunks and refuses out-of-scope queries.

---

## 2. System Architecture

### End-to-End Multi-Agent & RAG Pipeline

```mermaid
flowchart TD
    subgraph UI["Developer Portal & Reporting"]
        SUB["Code Submission (Python / Java)"]
        PORTAL["Streamlit Findings Portal (4 Tabs: Overview, Findings, PR Summary, Chat)"]
        PDF["PDF Report Generator (app/report_generator.py)"]
    end

    subgraph ORCH["Multi-Agent Orchestrator (agents/orchestrator.py)"]
        PARSE["Syntax Pre-Validation (python_parser.py / java_parser.py)"]
        PAR_START["Parallel Dispatch (ThreadPoolExecutor, 30s timeout)"]
        CA["Code Analysis Agent (agents/code_analysis.py)"]
        SEC["Security Agent (agents/security.py)"]
        MERGE["Merge, Deduplicate & Sort Findings"]
        REM["Remediation Agent (agents/remediation_agent.py)"]
        PRS["PR Summary Agent (agents/pr_summary_agent.py)"]
    end

    subgraph RAG["Offline Knowledge Base & Hybrid RAG Pipeline"]
        KBDOCS["KB Documents (kb/docs/: 13 files)"]
        CHUNK["Chunking (RecursiveCharacterTextSplitter: 800/100)"]
        EMB["Embedding (all-MiniLM-L6-v2, 384-dim)"]
        CHROMA["Vector Store (ChromaDB: owasp_security_rules, 113 chunks)"]
        HYB["Hybrid Retrieval (Over-fetch max(3k,10) + 0.72 Dense / 0.28 Lexical)"]
        CHAT["Chat Assistant (agents/chat_assistant.py)"]
    end

    SUB --> PARSE
    PARSE --> PAR_START
    PAR_START --> CA
    PAR_START --> SEC
    CA --> MERGE
    SEC --> MERGE
    MERGE --> REM
    REM --> PRS
    PRS --> PORTAL
    PORTAL --> PDF

    KBDOCS --> CHUNK
    CHUNK --> EMB
    EMB --> CHROMA
    CHROMA --> HYB
    HYB --> CHAT
    HYB -. "Rule Evidence (k=1)" .-> SEC
    HYB -. "Remediation Refs (k=2)" .-> REM
    PRS -. "AnalysisResult Context" .-> CHAT
    CHAT <--> PORTAL
```

### Architectural Highlights
- **Offline-First Execution:** `kb/retriever.py` and `app/app.py` set `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1` so locally cached `all-MiniLM-L6-v2` weights load without network round-trips.
- **Process-Level Singletons & Caching:** `retriever_singleton()` caches the embedding model and ChromaDB client per process. `SecurityAgent` caches KB evidence per rule ID (`_EVIDENCE_CACHE`), and `RemediationAgent` caches KB references per `(title, cwe_id)` (`_KB_CACHE`).
- **Graceful Degradation:** Every agent catches internal exceptions; if `CodeAnalysisAgent` or `SecurityAgent` fails or times out, the orchestrator records the error in `run_status` and continues the pipeline with surviving findings.

---

## 3. Agent & Module Specifications

| Component | Module | Responsibility | Inputs | Outputs | Key Logic |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **BaseAgent & Parsers** | `agents/base.py`, `app/python_parser.py`, `app/java_parser.py` | Uniform agent contract and syntax pre-validation | `code: str`, `language: str` | `{"is_valid", "error", "metadata"}` | Parses Python via `ast.parse()` and Java via `javalang.parse.parse()` before analysis. |
| **Code Analysis Agent** | `agents/code_analysis.py` | Detects maintainability code smells & complexity defects | `code`, `language`, `filename` | `List[Finding]` (`CODE-NNN`) | AST checks for cyclomatic complexity, deep nesting, long functions/files, God classes, parameter counts, duplicate code blocks, broad exception catches, magic numbers, unused imports/variables, naming, and missing docstrings/Javadoc. |
| **Security Agent** | `agents/security.py` | Detects OWASP Top 10:2025 / CWE vulnerabilities | `code`, `language`, `filename` | `List[Finding]` (`SEC-NNN`) | Executes `22` registered rules (`11` Python + `11` Java), source-to-sink taint analysis, Shannon entropy + known-token secret matching, line-preserving Java comment stripping, CVSS-style scoring, and cached RAG evidence lookup. |
| **Orchestrator** | `agents/orchestrator.py` | Coordinates parallel scan, merge, remediation, summary & chat factory | `code`, `language`, `filename`, `timeout=30.0` | `AnalysisResult` | Dispatches `CodeAnalysisAgent` + `SecurityAgent` in a `ThreadPoolExecutor`, deduplicates overlapping same-type spans (keeping higher `(severity_score, confidence)`), sorts by `(-severity_score, line_start, line_end)`, then sequences `RemediationAgent` and `PRSummaryAgent`. |
| **Remediation Agent** | `agents/remediation_agent.py` | Generates targeted patches and runs two-tier verification | `code`, `language`, `findings`, `filename` | `List[RemediationResult]` (up to `50` findings) | Applies deterministic Python/Java templates (SQLi, CMDi, XSS, secrets, weak crypto, deserialization, path traversal, TLS, CSRF, insecure auth, BAC, debug mode, broad exceptions, magic numbers), attaches KB references, and self-verifies each patch. |
| **PR Summary Agent** | `agents/pr_summary_agent.py` | Synthesizes executive overview, health score, and PR markdown | `findings`, `remediations`, `filename`, `language` | `PRSummary` + `CodeHealthScore` | Computes capped deterministic health score (`0–100`, Grade `A–F`), prioritizes fixes by `(severity desc, effort asc)`, extracts top 1–3 high/critical risks, and renders a PR Markdown report with unified diffs. |
| **Chat Assistant** | `agents/chat_assistant.py` | RAG-grounded conversational Q&A over analysis results & OWASP KB | `question: str`, `AnalysisResult`, `code`, `history` | `ChatResponse` | 6-class rule-based intent classifier (`finding_explanation`, `fix_request`, `concept_question`, `best_practice`, `summary_request`, `out_of_scope`), target finding resolution (ID, `#N`, line number, title, history), hybrid retrieval, grounding check (`score >= 0.25`), and 2–3 follow-up prompts. |
| **Findings Portal** | `app/app.py`, `app/ui_components.py` | Interactive dark-themed 4-tab Streamlit UI | Pasted or uploaded `.py`/`.java` (`<= 200 KB` max validation limit) | Interactive UI + JSON / MD / HTML / PDF exports | Persists `AnalysisResult`, `ReviewReport`, and `chat_history` in `st.session_state`; renders SVG health gauge, severity donut, multi-filter findings explorer with Before/After diffs, line-highlighted code viewer, and chat tab. |
| **PDF Report Generator** | `app/report_generator.py` | Generates multi-page PDF code review report | `result`, `source_code`, `filename`, `language` | `bytes` (PDF starting with `%PDF`) | Uses ReportLab (`SimpleDocTemplate`, `letter` size) + Matplotlib (`Agg` backend) to build Cover Page + 6 numbered sections (7 sections total), severity-colored tables, embedded bar/pie chart, wrapped monospace snippets, XML/Unicode sanitization, and paginated footers. |

### Registered Security Rules (`agents/security.py` — 22 Rules)

| Language | Rule IDs & Covered CWEs (11 Python / 11 Java) |
| :--- | :--- |
| **Python (11)** | `SEC-PY-SQLI` (`CWE-89`, CRITICAL), `SEC-PY-CMDI` (`CWE-78`, CRITICAL), `SEC-PY-XSS` (`CWE-79`, HIGH), `SEC-PY-SECRET` (`CWE-798`, HIGH), `SEC-PY-CRYPTO` (`CWE-327`, HIGH), `SEC-PY-DESERIAL` (`CWE-502`, CRITICAL), `SEC-PY-TRAVERSAL` (`CWE-22`, HIGH), `SEC-PY-SSRF-TLS` (`CWE-295`, HIGH), `SEC-PY-AUTH-CONFIG` (`CWE-209`, HIGH), `SEC-PY-CSRF` (`CWE-352`, HIGH), `SEC-PY-INSECURE-AUTH` (`CWE-287`, HIGH) |
| **Java (11)** | `SEC-JV-SQLI` (`CWE-89`, CRITICAL), `SEC-JV-CMDI` (`CWE-78`, CRITICAL), `SEC-JV-XSS` (`CWE-79`, HIGH), `SEC-JV-SECRET` (`CWE-798`, HIGH), `SEC-JV-CRYPTO` (`CWE-327`, HIGH), `SEC-JV-DESERIAL` (`CWE-502`, CRITICAL), `SEC-JV-TRAVERSAL` (`CWE-22`, HIGH), `SEC-JV-SSRF-TLS` (`CWE-295`, HIGH), `SEC-JV-AUTH-CONFIG` (`CWE-352`, HIGH), `SEC-JV-INSECURE-AUTH` (`CWE-287`, HIGH), `SEC-JV-BAC` (`CWE-862`, HIGH) |

### Code Quality Thresholds (`agents/code_analysis.py`)

| Constant | Threshold | Notes |
| :--- | :---: | :--- |
| `MAX_COMPLEXITY` | `10` | Cyclomatic complexity per function/method (`> 15` escalates to `HIGH`) |
| `MAX_FUNCTION_LINES` | `50` | Maximum lines per function/method |
| `MAX_FILE_LINES` | `300` | Maximum lines per source file |
| `MAX_NESTING_DEPTH` | `4` | Maximum nested control-flow depth |
| `MAX_PARAMETERS` | `5` | Maximum parameters (`self`/`cls` excluded in Python) |
| `MAX_CLASS_METHODS` | `10` | Maximum domain methods per class (Python dunder methods excluded) |
| `MAX_CLASS_LINES` | `200` | Maximum lines per class before God Class alert |
| `MIN_DUPLICATE_LINES` | `6` | Minimum consecutive normalized lines; overlapping spans merged |
| `ALLOWED_MAGIC_NUMBERS` | `{0, 1, 2, -1, 100, 0.0, 1.0}` | Exempts keyword args, `UPPER_CASE` constants, and `secrets.token_*` / `os.urandom` byte-length args |
| Java Javadoc Exemption | Anonymous inner classes | Skips `MethodDeclaration` nodes with a `javalang.tree.ClassCreator` ancestor |

---

## 4. Data Models, Severity Scoring & Health Score Formulas

### Core Pydantic Models (`app/schemas.py`)
- **`SeverityLevel` (`Enum`):** `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` (case-insensitive validator on `Finding.severity`).
- **`OWASPCategory` (`Enum`):** Full OWASP Top 10:2025 taxonomy (`A01:2025-Broken Access Control` through `A10:2025-Mishandling of Exceptional Conditions`).
- **`Finding`:** Unified defect contract (`id`, `title`, `category`, `agent`, `severity`, `severity_score [0.0–10.0]`, `file`, `line_start`, `line_end`, `code_snippet`, `explanation`, `suggestion`, `confidence [0.0–1.0]`, `source`, optional `owasp_category`, `cwe_id`, `evidence`).
- **`RemediationResult`:** `finding_id`, `explanation`, `fix_summary`, `original_code`, `corrected_code`, `best_practice`, `references`, `verified`, `verification_note`, `confidence`.
- **`CodeHealthScore`:** `score [0–100]`, `grade [A–F]`, `breakdown_by_severity`, `penalty_details`.
- **`PrioritizedFix` & `PRSummary`:** `executive_overview`, `severity_breakdown`, `top_risks`, `prioritized_fixes`, `health_score`, `markdown`.
- **`AnalysisResult`:** Top-level orchestrator output combining `findings`, `counts_by_severity`, `counts_by_agent`, `per_agent_runtime`, `run_status`, `remediations`, `pr_summary`, and `health_score`.
- **`ChatMessage`, `Citation`, `ChatResponse`:** Conversational history, KB chunk citation (`source`, `section`, `chunk_id`, `snippet`, `relevance_score`), `related_finding_ids`, `grounded`, `follow_up_suggestions`, and `intent`.

### Security Severity Scoring (`agents/security.py`)
`calculate_severity_score(cwe_id, severity, is_tainted)` maps each CWE to a CVSS v3.1-style base score (`CWE-89/78/502: 9.8`, `CWE-22/918: 8.6`, `CWE-798: 8.5`, `CWE-352: 8.1`, `CWE-79/327/328/295/209: 7.5`, `CWE-330: 6.5`; fallback tier defaults `CRITICAL=9.5, HIGH=8.0, MEDIUM=5.5, LOW=3.0, INFO=1.0`). When `is_tainted` is `False` and `base > 5.0`, the score is reduced by `1.0` (floored at `4.0`) to reflect unconfirmed taint flow.

Hardcoded secret detection uses Shannon entropy:

$$H(S) = -\sum_{i=1}^{k} p_i \log_2 p_i$$

combined with `SECRET_KEYWORD_PATTERN` variable/attribute matching and `KNOWN_TOKEN_PATTERN` matching (AWS `AKIA...`, Stripe `sk_live_...`, GitHub `ghp_...`, and PEM private key headers) evaluated independently of variable naming.

### Code Quality Severity Scoring (`agents/code_analysis.py`)
`calculate_quality_score(rule_type, severity)` assigns deterministic scores: `god_class=8.0`, `cyclomatic_complexity=7.5`, `llm_design_smell=6.5`, `deep_nesting=6.0`, `long_function=5.5`, `duplicate_code=5.5`, `too_many_parameters=5.0`, `broad_exception=5.0`, `long_file=4.5`, `unused_import/variable=3.0`, `missing_docstring=2.5`, `poor_naming/magic_number=2.0`.

### Deterministic Code Health Score (`agents/pr_summary_agent.py` & `app/report_generator.py`)

Starting from a base score of `100`, penalties are deducted per severity tier with diminishing-returns caps so a high count of minor smells cannot mask or overwhelm critical vulnerabilities:

$$\text{Penalty}_{\text{tier}} = \min\big(n_{\text{tier}} \times w_{\text{tier}},\; \text{Cap}_{\text{tier}}\big)$$

$$\text{Health Score} = \max\left(0,\; 100 - \sum_{\text{tier}} \text{Penalty}_{\text{tier}}\right)$$

| Severity Tier | Weight (`w`) | Diminishing-Returns Cap | Max Findings Before Cap |
| :--- | :---: | :---: | :---: |
| **CRITICAL** | `15` pts | `45` pts | `3` |
| **HIGH** | `8` pts | `32` pts | `4` |
| **MEDIUM** | `4` pts | `20` pts | `5` |
| **LOW** | `1` pt | `10` pts | `10` |
| **INFO** | `0` pts | `0` pts | — |

**Letter Grade Scale:** `A` (`90–100`), `B` (`80–89`), `C` (`70–79`), `D` (`60–69`), `F` (`< 60`).

### Two-Tier Remediation Self-Verification (`agents/remediation_agent.py`)
1. **Tier 1 (Syntax Validation):** Replaces the target line span in the full source file and validates syntax via `validate_python` (`ast.parse`) or `validate_java` (`javalang`).
2. **Tier 2 (Detector Regression Re-Scan):** Re-runs `SecurityAgent` or `CodeAnalysisAgent` on the patched file and confirms that the targeted finding disappears on the patched line range AND that the count of `CRITICAL` findings does not increase above `baseline_critical_count`.

---

## 5. Knowledge Base Contents & RAG Pipeline Parameters

### Knowledge Base Inventory (`kb/docs/` — 13 Documents, 113 Indexed Chunks)
- **OWASP Top 10:2025 Reference Guides (10 files):**
  - `A01_broken_access_control.md`, `A02_security_misconfiguration.md`, `A03_software_supply_chain_failures.md`, `A04_cryptographic_failures.md`, `A05_injection.md`, `A06_insecure_design.md`, `A07_authentication_failures.md`, `A08_software_or_data_integrity_failures.md`, `A09_security_logging_and_alerting_failures.md`, `A10_mishandling_of_exceptional_conditions.md`
- **Focused Cheatsheets & Clean Code Guides (3 files):**
  - `code_smells_and_clean_code.md`, `owasp_secrets_cheatsheet.txt`, `owasp_sqli_cheatsheet.txt`

### Ingestion & Retrieval Parameters (`kb/ingest.py`, `kb/retriever.py`, `agents/chat_assistant.py`)

| Parameter | Value | Implementation Detail |
| :--- | :--- | :--- |
| Text Splitter | `RecursiveCharacterTextSplitter` | `chunk_size=800`, `chunk_overlap=100`, separators `["\n## ", "\n### ", "\n\n", "\n", " ", ""]` |
| Chunk IDs | Deterministic SHA-256 | `{clean_stem}_{chunk_index}_{sha256[:8]}` enabling idempotent `collection.upsert()` |
| Embedding Model | `all-MiniLM-L6-v2` | Local `sentence-transformers` 384-dim dense vectors (`batch_size=32`) |
| Vector Store | ChromaDB `PersistentClient` | Path: `kb/chroma_db/`, collection: `owasp_security_rules`, metric: `hnsw:space=cosine` |
| Indexed Chunks | `113` | Verified via `Retriever().collection.count()` |
| Candidate Over-Fetch | `min(max(k * 3, 10), total_chunks)` | Retrieves dense top candidates prior to lexical reranking |
| Hybrid Reranking | `0.72 * dense + 0.28 * lexical_score` | `lexical_score = min(1.0, 0.50 * text_overlap + 1.15 * source_filename_overlap)` on stop-word-filtered tokens (`len >= 3`) |
| Grounding Threshold | `MIN_RELEVANCE_THRESHOLD = 0.25` | `ChatAssistant` requires retrieved chunk relevance `>= 0.25` to mark `grounded=True` |

---

## 6. Setup, Run Instructions, Project Structure & Test Commands

### Prerequisites & Setup (Windows PowerShell)
- **OS / Runtime:** Windows with Python 3.10+ (project tested in local `venv` on Python 3.14).
- **Pinned Dependencies (`requirements.txt`):** `streamlit==1.65.0`, `pydantic==2.14.0`, `javalang==0.13.0`, `chromadb==1.5.9`, `sentence-transformers==6.1.0`, `langchain-text-splitters==1.1.3`, `pypdf==6.20.0`, `pytest==9.1.1`, `pyyaml==6.0.3`, `reportlab==5.1.0`, `matplotlib==3.11.2`.

```powershell
# 1. Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 2. Install pinned dependencies
pip install -r requirements.txt

# 3. Build / refresh the persistent ChromaDB knowledge base (idempotent, 113 chunks)
python kb/ingest.py

# 4. Launch the 4-tab Streamlit developer portal
streamlit run app/app.py
```

### Verification, Evaluation & Demo Commands

```powershell
# Run the full pytest test suite (127 tests across 11 test modules)
.\venv\Scripts\python.exe -m pytest tests -q

# Run the Milestone 4 end-to-end evaluation harness (7 dev samples + 20 RAG Qs + 3 OOS Qs + 7 PDFs)
.\venv\Scripts\python.exe tests/eval/run_eval.py

# Run the Milestone 2 planted-defect benchmark (10 samples in tests/samples/python & java)
.\venv\Scripts\python.exe tests/evaluate.py

# Regenerate the 3 demo PDF reports into docs/demo_outputs/
.\venv\Scripts\python.exe scripts/generate_demo_reports.py
```

### Project Directory Structure

```text
Code Review and Security Analysis/
├── agents/                     # Multi-agent core
│   ├── base.py                 # BaseAgent abstract contract & parser bridge
│   ├── code_analysis.py        # Python/Java AST code quality & smell analyzer
│   ├── security.py             # 22-rule OWASP/CWE scanner + taint + entropy + RAG evidence
│   ├── remediation_agent.py    # Automated patch templates + two-tier verification
│   ├── pr_summary_agent.py     # Deterministic health score, prioritization, PR markdown
│   ├── chat_assistant.py       # Grounded RAG conversational assistant
│   └── orchestrator.py         # Parallel runner, deduplication, pipeline coordinator
├── app/                        # Parsers, schemas, UI & PDF export
│   ├── app.py                  # 4-tab Streamlit developer portal
│   ├── ui_components.py        # Pure UI helpers, SVG gauges/donuts, filters, exports
│   ├── report_generator.py     # ReportLab + Matplotlib 7-section PDF generator
│   ├── report.py               # Markdown/HTML report helpers (Milestone 2 compatibility)
│   ├── python_parser.py        # Python AST syntax pre-validator
│   ├── java_parser.py          # Java javalang syntax pre-validator
│   └── schemas.py              # Pydantic v2 data contracts
├── kb/                         # Local RAG knowledge base
│   ├── docs/                   # 13 OWASP 2025 & Clean Code source documents
│   ├── ingest.py               # Chunking, embedding, ChromaDB upsert pipeline
│   ├── retriever.py            # Cached Retriever singleton + hybrid reranker
│   └── chroma_db/              # Persistent local vector store (gitignored)
├── scripts/
│   └── generate_demo_reports.py # Regenerates docs/demo_outputs/*.pdf
├── docs/                       # Technical docs, academic report, demo script, PDFs
└── tests/                      # 127 pytest tests + dev/heldout evaluation suites
    ├── eval/                   # run_eval.py + results/ (eval_report, optimization_log, heldout*)
    └── samples/                # Milestone 2 samples, M4 dev samples, M4 heldout samples
```

---

## 7. Security Note on Synthetic Test Fixtures

> **Important Security Notice:** All API keys, tokens, and credential strings appearing inside `tests/samples/` (including `tests/samples/heldout/`), `tests/test_security.py`, `tests/test_report_generator.py`, `tests/test_chat_assistant.py`, and `tests/test_remediation_and_pr_summary.py`—such as `AKIAIOSFODNN7EXAMPLE*`, `sk_live_51H8xYz9AbCdEfGhIjKlMnOpQrStUvWx`, `ghp_9f8e7d6c5b4a3210fedcba9876543210abcd`, and `xoxb-998877665544-aabbccddeeff112233`—are **deliberately fabricated, non-functional test fixtures** planted exclusively to verify `CWE-798` hardcoded-secret detection. No live credentials or `.env` files are stored in the repository (`.env` is excluded via `.gitignore`).

---

## 8. Known Limitations and Future Work

1. **Single-File Intraprocedural Analysis:** Current taint tracking (`extract_python_taint`, `extract_java_taint`) operates within a single file and does not trace cross-module call graphs, dependency injection containers, or ORM-level sanitizers across repositories.
2. **Structural & Multi-Line Remediation Coverage:** Structural code smells (`God Class`, `Long Method`, `Deep Control Flow Nesting`, `Duplicate Code Block`, `Too Many Parameters`) intentionally produce manual refactoring guidance rather than automated rewrites (`75.5%` specific fix rate on the dev set; `77.3%` on the post-fix held-out set). Additionally, multi-line remediation templates currently anchor on common variable names (e.g., `query =`) and two idioms caught by Step 2c (`yaml.load(..., Loader=yaml.UnsafeLoader)` in Python and anonymous `HostnameVerifier` blocks in Java) lack dedicated replacement templates, causing the post-fix held-out syntax-valid rate to dip from `100.0% (20/20)` to `95.5% (21/22)`.
3. **Rule-Based Chat Synthesis:** `ChatAssistant` operates fully offline via deterministic intent classification and KB chunk composition; while this guarantees `100.0%` out-of-scope refusal accuracy and zero hallucination, natural-language paraphrasing is more rigid than an LLM-backed synthesis layer.
4. **Java Parser Language Version Coverage:** `javalang==0.13.0` supports Java 8 syntax reliably but does not parse newer Java 17–21 constructs (such as `record`, `switch` expressions, or text blocks), requiring parser upgrades (e.g., Tree-sitter) for modern Java codebases.
5. **Future Work:** Integrate Tree-sitter for multi-language AST coverage (Java 17+, TypeScript/JavaScript, Go), add cross-file call-graph taint propagation, expand remediation templates for `yaml.UnsafeLoader` / Java TLS anonymous classes / arbitrary SQL variable names, and add GitHub Actions PR-comment bot integration.
