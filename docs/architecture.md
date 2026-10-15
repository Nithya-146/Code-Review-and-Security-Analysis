# Code Review Agent - Comprehensive System Architecture and Technical Design

## 1. Executive Summary & Objective
The Code Review Agent is an automated, multi-tiered Static Application Security Testing (SAST) system. Its primary mission is to detect, evaluate, and provide verifiable remediation steps for critical software security vulnerabilities—focusing on OWASP Top 10 categories including SQL Injection (CWE-89) and Hardcoded Sensitive Credentials (CWE-798).

Unlike purely probabilistic language model reviewers that suffer from hallucinations and inconsistent rule application, this architecture uses a hybrid pipeline:
1. Deterministic code parsing via Abstract Syntax Trees (AST) guarantees precise extraction of syntax elements, dangerous string concatenations, and sensitive variable identifiers without consuming LLM tokens.
2. Semantic Retrieval-Augmented Generation (RAG) grounds the LLM in authoritative, local OWASP security rules stored in a ChromaDB vector database.
3. State machine orchestration through LangGraph coordinates the inspection workflow, enforces deterministic error handling, and formats outputs into strict Pydantic schemas.

---

## 2. End-to-End System Workflow

### Stage 1: Submission Intake & Pre-Validation
- The intake layer accepts code snippets through automated test harnesses, developer toolings, or API endpoints.
- Submissions are encapsulated in structured data containers containing the raw source code text, the target programming language (Python or Java), and metadata such as the repository name, filename, and submission timestamp.
- Strict Pydantic models validate the input payload before any parsing or downstream inference begins. Submissions exceeding memory limits or lacking language designations are rejected at the perimeter.

### Stage 2: Deterministic AST Analysis & Signal Extraction
- Python Processing: The native `ast` engine builds an abstract syntax tree of the code. Custom node visitors traverse the tree to capture function names, imported modules, parameter structures, and high-risk expressions (such as `cursor.execute` calls paired with formatted f-strings, modulo `%` substitutions, or `.format()` calls).
- Java Processing: The Java parser uses structured tokenization and syntactic patterns to inspect JDBC queries (`Statement.executeQuery`, `Statement.executeUpdate`) containing string concatenations using the addition operator (`+`), as well as hardcoded credential assignments.
- Output: A deterministic metadata dictionary containing the suspicious line numbers, identified function names, concatenated query candidates, and candidate secret variable names.

### Stage 3: Semantic Knowledge Base & RAG Context Retrieval
- Local Vector Database: The system integrates an embedded, persistent ChromaDB instance housed within the local repository directory.
- Knowledge Source: Industry-standard security guidelines derived from OWASP Cheat Sheets for SQL Injection Prevention and Sensitive Credential Management are ingested, split into semantically coherent overlapping text chunks, and stored as high-dimensional vector embeddings.
- Retrieval Mechanism: When suspicious AST signals are identified during Stage 2, targeted query strings (such as "parameterized queries prevention" or "hardcoded password environment variables") are computed against ChromaDB using cosine similarity.
- Output: Top-ranked rule snippets, framework-specific code remediation examples, and official CWE definitions are retrieved to serve as ground-truth context for the analysis agent.

### Stage 4: LLM Security Analysis & Reasoning
- Grounded Prompt Construction: The analysis agent receives a carefully structured prompt comprising three unified context blocks:
  1. The raw developer code under review.
  2. The deterministic flags and line references provided by the AST parser.
  3. The exact OWASP prevention techniques retrieved from the vector database.
- Agent Role: The model analyzes the interaction between the suspicious lines and untrusted input paths. Rather than guessing vulnerabilities, the model validates whether the identified syntax violates the provided OWASP specifications.
- Remediation Synthesis: For every verified vulnerability, the agent formulates a concrete, non-vulnerable code rewrite using prepared statements or environment variable extractions.

### Stage 5: Output Validation, Scoring, and Aggregation
- Structured Schema Enforcement: The agent's output is parsed into a Pydantic `VulnerabilityReport` containing:
  - CWE identifier and vulnerability classification.
  - Severity assessment (CRITICAL, HIGH, MEDIUM, LOW) based on CVSS logic.
  - Exact file location and line numbers.
  - Detailed explanation of the attack vector.
  - Recommended fix and hardened replacement code.
- Quality Guard: If the model output fails schema validation, the orchestration framework automatically initiates a schema-correction loop before presenting findings to the developer.

---

## 3. Directory Layout and Component Responsibilities

- `app/schemas.py`: Contains all Pydantic models defining the contracts across the application, including input submissions, intermediate parser results, vulnerability findings, and final evaluation summaries.
- `app/python_parser.py`: Implements Python AST visitors that extract functional components, SQL operations, and detect string concatenations in database calls.
- `app/java_parser.py`: Analyzes Java source files for dangerous JDBC patterns and unencrypted secrets.
- `kb/sources/`: Plaintext source cheat sheets holding authoritative OWASP guidelines for security best practices.
- `kb/ingest.py`: Chunking and embedding pipeline responsible for indexing OWASP documents into the vector database.
- `kb/retriever.py`: Vector retrieval interface exposing semantic query functions for the agent pipeline.
- `docs/architecture.md`: System design, interface contracts, and execution lifecycle specifications.
- `docs/notes.md`: Operational developer logs, design decisions, and step-by-step progress tracking.
- `tests/`: Pytest test suite validating parser accuracy, schema integrity, and vector retrieval performance.

---

## 4. Key Design Decisions and Architectural Trade-offs

1. Deterministic AST First, LLM Second:
   Relying exclusively on large language models to spot vulnerabilities leads to false negatives on complex syntax and consumes high token overhead. By using native AST parsers first, high-risk patterns are flagged with zero latency and zero token cost, using the LLM solely for semantic reasoning, contextual risk verification, and code repair.

2. Embedded Local Vector Storage (ChromaDB):
   Using an embedded, local vector database ensures that the security analysis tool can execute fully offline or within secured enterprise CI/CD pipelines without sending proprietary codebase data to external third-party vector cloud services.

3. Strict Type Safety and Pydantic Contracts:
   Enforcing strict Pydantic schemas between every internal node guarantees that unstructured model text cannot break downstream reporting systems, IDE extensions, or automated CI/CD pipeline blockers.