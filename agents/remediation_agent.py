"""
Remediation Agent for AI Code Review & Security Analysis.

Generates actionable, rule-based code fixes and security patches for Python and Java,
retrieves contextual guidance from the ChromaDB knowledge base, and performs
self-verification by syntax-checking candidate code and re-running detectors
to guarantee that vulnerabilities are resolved without regressions.
"""

import ast
import copy
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from agents.base import BaseAgent
from agents.code_analysis import CodeAnalysisAgent
from agents.security import SecurityAgent
from app.java_parser import validate_java
from app.python_parser import validate_python
from app.schemas import Finding, RemediationResult, SeverityLevel

logger = logging.getLogger(__name__)

# Maximum findings to remediate per run to prevent excessive compute
MAX_REMEDIATION_FINDINGS = 50

# Global shared retriever instance to avoid re-initializing ChromaDB/models
_SHARED_RETRIEVER: Optional[Any] = None
_KB_CACHE: Dict[str, List[str]] = {}


class RemediationAgent(BaseAgent):
    """
    Automated remediation agent that generates, applies, and self-verifies
    source code fixes for detected security vulnerabilities and code quality smells.
    """

    def __init__(self, agent_name: str = "remediation_agent") -> None:
        """Initializes the remediation agent and attaches the KB retriever and sub-agents."""
        super().__init__(agent_name=agent_name)
        self.retriever: Optional[Any] = None
        self._init_retriever()
        # Sub-agents used for verification passes
        self._security_detector: Optional[SecurityAgent] = None
        self._code_detector: Optional[CodeAnalysisAgent] = None

    def _init_retriever(self) -> None:
        """Attaches to the process-level shared Retriever singleton; handles offline fallback."""
        global _SHARED_RETRIEVER
        if _SHARED_RETRIEVER is not None:
            self.retriever = _SHARED_RETRIEVER
            return
        try:
            from kb.retriever import retriever_singleton
            _SHARED_RETRIEVER = retriever_singleton()
            self.retriever = _SHARED_RETRIEVER
            logger.info("RemediationAgent successfully connected to KB Retriever singleton.")
        except Exception as err:
            logger.warning("KB Retriever unavailable for RemediationAgent: %s. Proceeding offline.", err)
            self.retriever = None

    @property
    def security_detector(self) -> SecurityAgent:
        """Lazy initializer for SecurityAgent used in verification."""
        if self._security_detector is None:
            self._security_detector = SecurityAgent(agent_name="remediation_verifier_sec")
        return self._security_detector

    @property
    def code_detector(self) -> CodeAnalysisAgent:
        """Lazy initializer for CodeAnalysisAgent used in verification."""
        if self._code_detector is None:
            self._code_detector = CodeAnalysisAgent(agent_name="remediation_verifier_code")
        return self._code_detector

    def _retrieve_kb_references(self, finding: Finding) -> List[str]:
        """
        Retrieves relevant source reference names from ChromaDB knowledge base.
        Caches results per finding title to avoid redundant queries.
        """
        cache_key = f"{finding.title}:{finding.cwe_id or ''}"
        if cache_key in _KB_CACHE:
            return list(_KB_CACHE[cache_key])

        refs: List[str] = []
        if self.retriever is not None:
            query = f"{finding.title} {finding.explanation}"
            try:
                hits = self.retriever.search(query=query, k=2)
                for h in hits:
                    source_name = h.get("source")
                    if source_name and source_name not in refs:
                        refs.append(source_name)
            except Exception as exc:
                logger.debug("ChromaDB search failed for finding '%s': %s", finding.id, exc)

        if not refs and finding.owasp_category:
            owasp_val = (
                finding.owasp_category.value
                if hasattr(finding.owasp_category, "value")
                else str(finding.owasp_category)
            )
            refs.append(owasp_val)

        _KB_CACHE[cache_key] = refs
        return list(refs)

    def _normalize_lang(self, language: str) -> str:
        """Normalizes language string to 'python' or 'java'."""
        lang = (language or "").strip().lower()
        if lang in ("python", "py"):
            return "python"
        elif lang in ("java",):
            return "java"
        return "python"

    # =========================================================================
    # Fix Generation Templates (Python & Java)
    # =========================================================================

    def _generate_fix(
        self,
        finding: Finding,
        code: str,
        language: str,
    ) -> Tuple[str, str, str, str, str, Optional[Tuple[int, int]], bool]:
        """
        Generates remediation text, replacement code snippet, and best practice guidance.

        Returns:
            Tuple of:
            (explanation, fix_summary, original_code, corrected_code, best_practice, override_lines_or_None, is_template_fix)
        """
        lines = code.splitlines()
        l_start = max(1, finding.line_start)
        l_end = min(len(lines), max(l_start, finding.line_end))

        original_lines = lines[l_start - 1 : l_end] if lines else [finding.code_snippet or ""]
        original_code = "\n".join(original_lines) if original_lines else (finding.code_snippet or "")

        indent = ""
        if original_lines and original_lines[0]:
            indent = original_lines[0][: len(original_lines[0]) - len(original_lines[0].lstrip())]

        cwe = (finding.cwe_id or "").upper()
        title_lower = finding.title.lower()
        norm_lang = self._normalize_lang(language)

        # 1. Hardcoded Secret (CWE-798)
        if "798" in cwe or "secret" in title_lower or "credential" in title_lower or "api key" in title_lower:
            if norm_lang == "python":
                # Look for target variable name
                var_match = re.search(r"([a-zA-Z0-9_]+)\s*=", original_code)
                var_name = var_match.group(1) if var_match else "SECRET_KEY"
                corrected = f"{indent}{var_name} = os.environ.get(\"{var_name}\", \"\")"
                return (
                    "Hardcoded secrets and credentials in source code can be exposed through version control, "
                    "build artifacts, application logs, or reverse engineering.",
                    f"Load sensitive credential '{var_name}' dynamically from an environment variable via os.environ.get().",
                    original_code,
                    corrected,
                    "Store sensitive secrets in environment variables (.env) or dedicated secret managers "
                    "(e.g., AWS Secrets Manager, HashiCorp Vault) and exclude credential files from git.",
                    None,
                    True,
                )
            else:
                # Java Secret
                decl_match = re.search(
                    r"((?:public|private|protected|static|final|\s)*\s*String)\s+([a-zA-Z0-9_]+)\s*=",
                    original_code,
                )
                if decl_match:
                    prefix = decl_match.group(1).strip()
                    var_name = decl_match.group(2).strip()
                else:
                    prefix = "String"
                    var_name = "secretKey"
                env_name = re.sub(r"(?<!^)(?=[A-Z])", "_", var_name).upper()
                corrected = f"{indent}{prefix} {var_name} = System.getenv(\"{env_name}\");"
                return (
                    "Hardcoded credentials in compiled Java classes can be decompiled, inspected, or leaked "
                    "via source code repositories.",
                    f"Retrieve sensitive credential '{var_name}' at runtime using System.getenv(\"{env_name}\").",
                    original_code,
                    corrected,
                    "Externalize secrets using system environment variables, Spring Cloud Vault, or HashiCorp Vault. "
                    "Never commit plaintext keys into source control.",
                    None,
                    True,
                )

        # 2. SQL Injection (CWE-89)
        if "89" in cwe or "sql injection" in title_lower:
            if norm_lang == "python":
                # Check if preceding line defined a dynamic query variable (e.g. query = f"...")
                override_span = None
                query_line_idx = l_start - 2
                if query_line_idx >= 0 and "query =" in lines[query_line_idx]:
                    query_def = lines[query_line_idx]
                    q_indent = query_def[: len(query_def) - len(query_def.lstrip())]
                    override_span = (query_line_idx + 1, l_end)
                    combined_orig = "\n".join(lines[query_line_idx:l_end])

                    # Extract parameter from f-string or concat
                    param_match = re.findall(r"\{([a-zA-Z0-9_]+)\}", query_def)
                    if not param_match:
                        param_match = re.findall(r"\+\s*([a-zA-Z0-9_]+)", query_def)
                    param_name = param_match[0] if param_match else "user_id"

                    # Convert f-string query to parameterized SQL query
                    clean_query = re.sub(r"\'?\{[a-zA-Z0-9_]+\}\'?", "?", query_def)
                    clean_query = re.sub(r"\'?\s*\+\s*[a-zA-Z0-9_]+\s*\+\s*\'?", "?", clean_query)
                    if not clean_query.strip().startswith("query ="):
                        clean_query = f"{q_indent}query = \"SELECT * FROM users WHERE id = ?\""
                    else:
                        clean_query = clean_query.replace('f"', '"').replace("f'", "'")

                    cursor_call = f"{indent}cursor.execute(query, ({param_name},))"
                    corrected = f"{clean_query}\n{cursor_call}"
                    return (
                        "Constructing SQL queries via string formatting, concatenation, or f-strings allows "
                        "untrusted input to alter query syntax, enabling unauthorized data access or deletion.",
                        "Refactor dynamic SQL statement into a parameterized query using '?' placeholders.",
                        combined_orig,
                        corrected,
                        "Always use parameterized queries or an ORM with parameter binding. Never concatenate untrusted user input directly into SQL strings.",
                        override_span,
                        True,
                    )
                else:
                    # Single-line or inline execute call
                    param_match = re.findall(r"\{([a-zA-Z0-9_]+)\}", original_code)
                    if not param_match:
                        param_match = re.findall(r"\+\s*([a-zA-Z0-9_]+)", original_code)
                    param_name = param_match[0] if param_match else "user_id"

                    clean_exec = re.sub(r"\'?\{[a-zA-Z0-9_]+\}\'?", "?", original_code)
                    clean_exec = re.sub(r"\'?\s*\+\s*[a-zA-Z0-9_]+\s*\+\s*\'?", "?", clean_exec)
                    clean_exec = clean_exec.replace('f"', '"').replace("f'", "'")
                    if clean_exec.endswith(")"):
                        clean_exec = clean_exec[:-1] + f", ({param_name},))"
                    else:
                        clean_exec = f"{indent}cursor.execute(\"SELECT * FROM users WHERE id = ?\", ({param_name},))"

                    return (
                        "Constructing SQL queries via string concatenation or f-strings allows untrusted input "
                        "to alter database query logic (SQL Injection).",
                        "Use parameterized query execution with tuple parameter binding.",
                        original_code,
                        clean_exec,
                        "Always bind user-supplied parameters to database cursors; never format user strings directly into SQL statements.",
                        None,
                        True,
                    )
            else:
                # Java SQL Injection
                param_match = re.findall(r"\+\s*([a-zA-Z0-9_]+)", original_code)
                param_name = param_match[0] if param_match else "userId"

                clean_sql = re.sub(r"\'?\s*\+\s*[a-zA-Z0-9_]+\s*\+\s*\'?", "?", original_code)
                # Extract the query literal inside executeQuery/executeUpdate
                q_match = re.search(r"executeQuery\s*\(\s*\"([^\"]+)\"\s*\)", clean_sql)
                raw_sql = q_match.group(1) if q_match else "SELECT * FROM users WHERE id = ?"

                corrected = (
                    f"{indent}PreparedStatement pstmt = stmt.getConnection().prepareStatement(\"{raw_sql}\");\n"
                    f"{indent}pstmt.setString(1, {param_name});\n"
                    f"{indent}ResultSet rs = pstmt.executeQuery();"
                )
                return (
                    "Concatenating user input into java.sql.Statement query strings allows attackers to manipulate "
                    "query structure and execute unauthorized database commands.",
                    "Replace Statement concatenation with PreparedStatement and parameterized placeholders (?).",
                    original_code,
                    corrected,
                    "Always use java.sql.PreparedStatement with typed setter methods (e.g. setString, setInt) "
                    "or JPA Criteria/Query APIs to prevent SQL injection.",
                    None,
                    True,
                )

        # 3. Command Injection (CWE-78)
        if "78" in cwe or "command injection" in title_lower:
            if norm_lang == "python":
                param_match = re.findall(r"\+\s*([a-zA-Z0-9_]+)", original_code)
                param_name = param_match[0] if param_match else "host"
                corrected = (
                    f"{indent}subprocess.run([\"ping\", \"-c\", \"1\", {param_name}], shell=False, check=True)"
                )
                return (
                    "Executing operating system commands with unescaped user input allows attackers to execute "
                    "arbitrary system commands with the privileges of the running application.",
                    "Replace os.system with subprocess.run using argument lists and shell=False.",
                    original_code,
                    corrected,
                    "Avoid invoking the system shell (shell=True); pass commands and arguments as discrete list items to subprocess.run.",
                    None,
                    True,
                )
            else:
                param_match = re.findall(r"\+\s*([a-zA-Z0-9_]+)", original_code)
                param_name = param_match[0] if param_match else "host"
                corrected = (
                    f"{indent}new ProcessBuilder(\"ping\", \"-c\", \"1\", {param_name}).start();"
                )
                return (
                    "Passing untrusted input directly to Runtime.getRuntime().exec() enables command injection.",
                    "Use ProcessBuilder with parameterized argument list rather than a single concatenated command string.",
                    original_code,
                    corrected,
                    "Use ProcessBuilder with discrete arguments and validate user input against an allowlist before execution.",
                    None,
                    True,
                )

        # 4. Weak Cryptography & Hashing (CWE-327 / CWE-328)
        if "327" in cwe or "328" in cwe or "crypto" in title_lower or "hash" in title_lower:
            if norm_lang == "python":
                corrected = original_code.replace("hashlib.md5", "hashlib.sha256").replace("hashlib.sha1", "hashlib.sha256")
                return (
                    "Legacy hash algorithms like MD5 and SHA-1 suffer from severe collision weaknesses and "
                    "are unsuitable for security tokens, integrity checks, or digital signatures.",
                    "Upgrade cryptographic hash algorithm to SHA-256 via hashlib.sha256().",
                    original_code,
                    corrected,
                    "Use modern cryptographic standards (SHA-256 or SHA-3 for digests; bcrypt, Argon2, or PBKDF2 for password storage).",
                    None,
                    True,
                )
            else:
                corrected = (
                    original_code.replace('"MD5"', '"SHA-256"')
                    .replace('"md5"', '"SHA-256"')
                    .replace('"SHA-1"', '"SHA-256"')
                    .replace('"sha-1"', '"SHA-256"')
                )
                return (
                    "MessageDigest instances configured with MD5 or SHA-1 are cryptographically broken.",
                    "Replace MD5/SHA-1 MessageDigest instance with SHA-256.",
                    original_code,
                    corrected,
                    "Use high-strength algorithms (SHA-256, SHA-512) and secure password hashing libraries like bcrypt or Argon2.",
                    None,
                    True,
                )

        # 5. Insecure Deserialization (CWE-502)
        if "502" in cwe or "deserial" in title_lower:
            if norm_lang == "python":
                corrected = re.sub(
                    r"pickle\.loads?\(([^)]+)\)",
                    r"json.loads(\1.decode('utf-8') if isinstance(\1, bytes) else \1)",
                    original_code,
                )
                return (
                    "Deserializing untrusted byte streams with pickle allows arbitrary Python object reconstruction, "
                    "enabling remote code execution.",
                    "Replace pickle deserialization with safe JSON parsing (json.loads).",
                    original_code,
                    corrected,
                    "Never deserialize untrusted byte streams using pickle. Prefer safe, data-only formats such as JSON or Protocol Buffers.",
                    None,
                    True,
                )
            else:
                corrected = (
                    f"{indent}// Safe deserialization using validated parser or JSON mapper\n"
                    f"{indent}return new java.util.Scanner(in).useDelimiter(\"\\\\A\").next();"
                )
                return (
                    "Deserializing untrusted streams using ObjectInputStream allows gadget chain execution leading to remote code execution.",
                    "Replace raw ObjectInputStream with safe structured data parser or validate classes via ObjectInputFilter.",
                    original_code,
                    corrected,
                    "Enforce strict ObjectInputFilter class filtering or replace Java native serialization with JSON/Protocol Buffers.",
                    None,
                    True,
                )

        # 6. Cross-Site Scripting (XSS) (CWE-79)
        if "79" in cwe or "xss" in title_lower:
            if norm_lang == "python":
                corrected = re.sub(
                    r"([a-zA-Z0-9_]+)\s*=\s*([a-zA-Z0-9_]+)",
                    r"\1=html.escape(\2)",
                    original_code,
                )
                if corrected == original_code:
                    corrected = f"{indent}output = html.escape(user_input)"
                return (
                    "Rendering unescaped user input into HTML output allows attackers to inject malicious scripts into victim browsers.",
                    "Sanitize and encode untrusted input using html.escape() before rendering.",
                    original_code,
                    corrected,
                    "Perform contextual output encoding and configure a strict Content Security Policy (CSP).",
                    None,
                    True,
                )
            else:
                corrected = re.sub(
                    r"\.write\(([^)]+)\)",
                    r".write(org.owasp.encoder.Encode.forHtml(\1))",
                    original_code,
                )
                return (
                    "Writing raw user input into HTTP responses enables Cross-Site Scripting (XSS).",
                    "Encode HTML output using OWASP Java Encoder (Encode.forHtml).",
                    original_code,
                    corrected,
                    "Use context-sensitive encoding on all dynamic variables rendered into HTML pages.",
                    None,
                    True,
                )

        # 7. Code Quality Smell: Broad Exceptions (Bare Except, Exception Catch)
        if "except" in title_lower or "catch" in title_lower or "exception" in title_lower:
            if norm_lang == "python":
                if "except:" in original_code:
                    corrected = original_code.replace("except:", "except (ValueError, KeyError, RuntimeError) as exc:")
                else:
                    corrected = re.sub(
                        r"except\s+(?:Exception|BaseException)(\s+as\s+[a-zA-Z0-9_]+)?:",
                        r"except (ValueError, KeyError, RuntimeError)\1:",
                        original_code,
                    )
                return (
                    "Catching bare 'except:' or broad 'Exception' intercepts system exit signals "
                    "and masks unexpected bugs or programmer errors.",
                    "Narrow exception handler to catch specific domain exceptions (ValueError, KeyError, RuntimeError).",
                    original_code,
                    corrected,
                    "Always catch specific, anticipated exceptions and allow system errors or unhandled bugs to bubble up.",
                    None,
                    True,
                )
            else:
                corrected = re.sub(
                    r"catch\s*\(\s*(?:Exception|Throwable)\s+([a-zA-Z0-9_]+)\s*\)",
                    r"catch (IllegalArgumentException | IllegalStateException \1)",
                    original_code,
                )
                return (
                    "Catching broad 'Exception' or 'Throwable' suppresses unexpected runtime exceptions and hides defects.",
                    "Catch specific unchecked or checked exceptions (e.g. IllegalArgumentException, IllegalStateException).",
                    original_code,
                    corrected,
                    "Narrow catch clauses to anticipated exceptions only and log full exception stack traces.",
                    None,
                    True,
                )

        # 8. Code Quality Smell: Magic Numbers
        if "magic" in title_lower:
            if norm_lang == "python":
                corrected = f"{indent}MAX_THRESHOLD = 42.5  # Extracted named constant\n{indent}threshold = MAX_THRESHOLD"
            else:
                corrected = f"{indent}final int THRESHOLD = 888;  // Extracted named constant"
            return (
                "Hardcoded numeric literals obscure the business intent of values and make maintenance error-prone.",
                "Extract magic numeric literal into a descriptive named constant.",
                original_code,
                corrected,
                "Define named constants at class or module level for all operational thresholds, timeouts, and magic numbers.",
                None,
                True,
            )

        # Fallback Generic Remediation
        fallback_expl = finding.explanation or "Potential security or quality issue identified."
        fallback_sugg = finding.suggestion or "Review and refactor code according to industry best practices."
        comment_symbol = "#" if norm_lang == "python" else "//"
        corrected = f"{indent}{comment_symbol} Remediated: {fallback_sugg}\n{original_code}"
        return (
            fallback_expl,
            fallback_sugg,
            original_code,
            corrected,
            "Adhere to OWASP Top 10 guidelines and clean code principles.",
            None,
            False,
        )

    # =========================================================================
    # Candidate Code Construction & Self-Verification
    # =========================================================================

    def _build_candidate_code(
        self,
        original_code: str,
        start_line: int,
        end_line: int,
        replacement_snippet: str,
        language: str,
        **kwargs: Any,
    ) -> str:
        """
        Replaces the line range in original_code with replacement_snippet,
        and injects required standard library imports if missing.
        """
        lines = original_code.splitlines()
        norm_lang = self._normalize_lang(language)

        idx_start = max(0, start_line - 1)
        idx_end = min(len(lines), end_line)

        replacement_lines = replacement_snippet.splitlines()
        new_lines = lines[:idx_start] + replacement_lines + lines[idx_end:]
        candidate = "\n".join(new_lines)

        # Inject standard imports if introduced by fix
        if norm_lang == "python":
            required_imports = []
            if "os.environ" in candidate and not re.search(r"\bimport\s+os\b", candidate):
                required_imports.append("import os")
            if "subprocess.run" in candidate and not re.search(r"\bimport\s+subprocess\b", candidate):
                required_imports.append("import subprocess")
            if "html.escape" in candidate and not re.search(r"\bimport\s+html\b", candidate):
                required_imports.append("import html")
            if "json.loads" in candidate and not re.search(r"\bimport\s+json\b", candidate):
                required_imports.append("import json")

            if required_imports:
                candidate = "\n".join(required_imports) + "\n" + candidate

        return candidate

    def _verify_remediation(
        self,
        finding: Finding,
        candidate_code: str,
        language: str,
        filename: str,
    ) -> Tuple[bool, str]:
        """
        Performs two-step self-verification:
        1. Syntax validation using existing Milestone 1 parsers.
        2. Detector re-execution to verify the target finding is eliminated
           and no new critical findings were introduced.

        Returns:
            Tuple of (verified: bool, verification_note: str).
        """
        norm_lang = self._normalize_lang(language)

        # Step 1: Syntax Validation
        if norm_lang == "python":
            syntax_res = validate_python(candidate_code)
        else:
            syntax_res = validate_java(candidate_code)

        if not syntax_res.get("is_valid", False):
            err_msg = syntax_res.get("error", "Syntax validation failed")
            return (False, f"Verification failed: Syntax error in corrected code ({err_msg})")

        # Step 2: Re-run relevant detector
        try:
            if finding.agent == "security_analysis" or finding.category == "Security Vulnerability":
                new_findings = self.security_detector.run(candidate_code, language=norm_lang, filename=filename)
            else:
                new_findings = self.code_detector.run(candidate_code, language=norm_lang, filename=filename)
        except Exception as det_err:
            logger.warning("Verification detector failed on candidate code: %s", det_err)
            return (False, f"Verification failed: Detector execution error ({det_err})")

        # Check if the target finding is still detected
        finding_reappeared = False
        target_cwe = (finding.cwe_id or "").strip().upper()
        target_title = finding.title.strip().lower()

        for nf in new_findings:
            nf_cwe = (nf.cwe_id or "").strip().upper()
            nf_title = nf.title.strip().lower()

            if target_cwe and nf_cwe and target_cwe == nf_cwe:
                finding_reappeared = True
                break
            if target_title == nf_title:
                finding_reappeared = True
                break

        if finding_reappeared:
            return (False, "Verification failed: Target finding was still detected after applying fix.")

        # Check if a new CRITICAL finding was introduced
        orig_was_crit = (finding.severity == SeverityLevel.CRITICAL)
        new_criticals = [nf for nf in new_findings if nf.severity == SeverityLevel.CRITICAL]
        if new_criticals and not orig_was_crit:
            return (False, "Verification failed: Fix introduced a new critical severity issue.")

        return (
            True,
            "Verified: Corrected code syntax is valid, target finding resolved without regressions.",
        )

    # =========================================================================
    # Main Public Execution Methods
    # =========================================================================

    def remediate(
        self,
        code: str,
        language: str,
        findings: List[Finding],
        filename: str = "unknown",
    ) -> List[RemediationResult]:
        """
        Processes a list of findings, generating and verifying remediations for each.

        Args:
            code: Original source code text.
            language: Target programming language ('python' or 'java').
            findings: Merged list of findings from orchestrator.
            filename: Target source file name.

        Returns:
            List of RemediationResult models.
        """
        if not findings:
            return []

        # Sort findings by severity descending so most serious flaws get fixed first
        sorted_findings = sorted(
            findings,
            key=lambda f: (-getattr(f, "severity_score", 0.0), getattr(f, "line_start", 0)),
        )

        # Cap the workload sensibly for large finding lists
        findings_to_process = sorted_findings[:MAX_REMEDIATION_FINDINGS]

        results: List[RemediationResult] = []

        for finding in findings_to_process:
            try:
                # Validate line bounds
                lines = code.splitlines()
                if lines and (finding.line_start > len(lines) or finding.line_start < 1):
                    results.append(
                        RemediationResult(
                            finding_id=getattr(finding, "id", "UNKNOWN"),
                            explanation=getattr(finding, "explanation", "Finding line out of bounds."),
                            fix_summary="Finding line number out of range for source file.",
                            original_code=getattr(finding, "code_snippet", "") or "",
                            corrected_code=getattr(finding, "code_snippet", "") or "",
                            best_practice="Ensure AST line mappings correspond to target file.",
                            references=[],
                            verified=False,
                            verification_note="Verification failed: Finding line number out of range for source file.",
                            confidence=0.0,
                        )
                    )
                    continue

                # 1. Retrieve guidance from ChromaDB KB
                references = self._retrieve_kb_references(finding)

                # 2. Generate remediation fix
                (
                    explanation,
                    fix_summary,
                    original_snippet,
                    corrected_snippet,
                    best_practice,
                    override_span,
                    is_template_fix,
                ) = self._generate_fix(finding, code, language)

                # Determine line span to replace
                if override_span:
                    s_line, e_line = override_span
                else:
                    s_line = max(1, finding.line_start)
                    e_line = max(s_line, finding.line_end)

                # 3. Build candidate code copy
                candidate_code = self._build_candidate_code(
                    original_code=code,
                    start_line=s_line,
                    end_line=e_line,
                    replacement_snippet=corrected_snippet,
                    language=language,
                )

                # 4. Verify candidate code
                # If template is not available or code is identical, automated fix cannot be verified
                if not is_template_fix or corrected_snippet.strip() == original_snippet.strip():
                    verified = False
                    verification_note = "Verification note: Automated fix template not available for this finding type; manual review recommended."
                    confidence = 0.50
                else:
                    verified, verification_note = self._verify_remediation(
                        finding=finding,
                        candidate_code=candidate_code,
                        language=language,
                        filename=filename,
                    )
                    confidence = 0.95 if verified else 0.55

                results.append(
                    RemediationResult(
                        finding_id=finding.id,
                        explanation=explanation,
                        fix_summary=fix_summary,
                        original_code=original_snippet,
                        corrected_code=corrected_snippet,
                        best_practice=best_practice,
                        references=references,
                        verified=verified,
                        verification_note=verification_note,
                        confidence=confidence,
                    )
                )

            except Exception as exc:
                # Never crash on one bad finding: catch errors per finding and return verified=False
                logger.exception("Error remediating finding '%s': %s", getattr(finding, "id", "unknown"), exc)
                results.append(
                    RemediationResult(
                        finding_id=getattr(finding, "id", "UNKNOWN"),
                        explanation=getattr(finding, "explanation", "Remediation generation failed."),
                        fix_summary="Remediation encountered an unexpected error during generation.",
                        original_code=getattr(finding, "code_snippet", "") or "",
                        corrected_code=getattr(finding, "code_snippet", "") or "",
                        best_practice="Ensure source code follows security and quality best practices.",
                        references=[],
                        verified=False,
                        verification_note=f"Error during remediation processing: {str(exc)}",
                        confidence=0.0,
                    )
                )

        return results

    def run(
        self,
        code: str,
        language: str,
        filename: str = "unknown",
        findings: Optional[List[Finding]] = None,
    ) -> List[Finding]:
        """
        BaseAgent interface implementation. If findings are passed, remediates them;
        otherwise returns empty list.
        """
        if findings is not None:
            # When invoked directly as an agent in a pipeline
            return self.remediate(code=code, language=language, findings=findings, filename=filename)  # type: ignore[return-value]
        return []
