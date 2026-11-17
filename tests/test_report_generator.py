"""
Unit and Integration Tests for PDF Code Review Report Generator (Milestone 4, Step 1).

Validates app/report_generator.py:
- Valid PDF header (%PDF) and parseable structure via pypdf
- Presence of all required sections (cover page, executive overview, severity breakdown +
  embedded chart, findings summary table, detailed findings with OWASP + remediation fix,
  prioritized remediation roadmap Fix Now/Next/Later, overall code quality assessment)
- Zero-findings clean file handling
- Large-findings (100+) multi-page pagination
- Special characters (<, >, &, quotes, Latin-1, emojis) and very long unbroken code lines
- Missing remediation & serialized dict input (Streamlit session_state format)
- End-to-end integration with orchestrator.analyze() on planted_security.py
"""

import io
from pathlib import Path

from pypdf import PdfReader

from agents.orchestrator import analyze
from app.report_generator import generate_report
from app.schemas import (
    AnalysisResult,
    CodeHealthScore,
    Finding,
    OWASPCategory,
    PrioritizedFix,
    PRSummary,
    RemediationResult,
    SeverityLevel,
)


def _extract_all_text(pdf_bytes: bytes) -> tuple[PdfReader, str]:
    """Parses PDF bytes with pypdf and returns (PdfReader, full concatenated text)."""
    reader = PdfReader(io.BytesIO(pdf_bytes))
    full_text = "\n".join((page.extract_text() or "") for page in reader.pages)
    return reader, full_text


def _make_rich_result() -> tuple[AnalysisResult, str]:
    """Builds a realistic AnalysisResult containing findings across tiers, remediations, and PRSummary."""
    source_code = (
        "import sqlite3\n"
        "API_KEY = 'AKIAIOSFODNN7EXAMPLE12345'\n"
        "def get_user(conn, uid):\n"
        "    query = f\"SELECT * FROM users WHERE id = '{uid}'\"\n"
        "    return conn.cursor().execute(query).fetchone()\n"
        "def helper(x):\n"
        "    try:\n"
        "        return x * 42.5\n"
        "    except Exception:\n"
        "        return 0\n"
    )

    findings = [
        Finding(
            id="SEC-001",
            title="SQL Injection",
            category="Security Vulnerability",
            agent="security_analysis",
            severity=SeverityLevel.CRITICAL,
            severity_score=9.8,
            file="service.py",
            line_start=4,
            line_end=5,
            code_snippet="query = f\"SELECT * FROM users WHERE id = '{uid}'\"\nreturn conn.cursor().execute(query).fetchone()",
            explanation="User input is interpolated directly into an SQL query string.",
            suggestion="Use parameterized queries with '?' placeholders.",
            confidence=0.95,
            owasp_category=OWASPCategory.A05,
            cwe_id="CWE-89",
        ),
        Finding(
            id="SEC-002",
            title="Hardcoded Secret",
            category="Security Vulnerability",
            agent="security_analysis",
            severity=SeverityLevel.HIGH,
            severity_score=8.2,
            file="service.py",
            line_start=2,
            line_end=2,
            code_snippet="API_KEY = 'AKIAIOSFODNN7EXAMPLE12345'",
            explanation="Sensitive credential is embedded directly in source code.",
            suggestion="Load secrets from environment variables using os.environ.get().",
            confidence=0.92,
            owasp_category=OWASPCategory.A07,
            cwe_id="CWE-798",
        ),
        Finding(
            id="CODE-001",
            title="Broad Exception Handling",
            category="Code Smell",
            agent="code_analysis",
            severity=SeverityLevel.MEDIUM,
            severity_score=5.0,
            file="service.py",
            line_start=9,
            line_end=10,
            code_snippet="except Exception:\n    return 0",
            explanation="Catching generic Exception masks unexpected runtime bugs.",
            suggestion="Catch specific exception types such as ValueError or TypeError.",
            confidence=0.88,
        ),
        Finding(
            id="CODE-002",
            title="Magic Number",
            category="Maintainability",
            agent="code_analysis",
            severity=SeverityLevel.LOW,
            severity_score=2.5,
            file="service.py",
            line_start=8,
            line_end=8,
            code_snippet="return x * 42.5",
            explanation="Unexplained numeric literal reduces readability.",
            suggestion="Extract 42.5 into a named module constant.",
            confidence=0.80,
        ),
    ]

    remediations = [
        RemediationResult(
            finding_id="SEC-001",
            explanation="String interpolation in SQL allows attackers to alter query logic.",
            fix_summary="Replaced f-string SQL query with a parameterized query.",
            original_code="query = f\"SELECT * FROM users WHERE id = '{uid}'\"\nreturn conn.cursor().execute(query).fetchone()",
            corrected_code="query = 'SELECT * FROM users WHERE id = ?'\nreturn conn.cursor().execute(query, (uid,)).fetchone()",
            best_practice="Always bind untrusted variables via DB-API query parameters.",
            references=["owasp_sqli_cheatsheet.txt", "A05_injection.md"],
            verified=True,
            verification_note="Passed Python AST syntax check and SecurityAgent re-scan.",
            confidence=0.96,
        ),
        RemediationResult(
            finding_id="SEC-002",
            explanation="Hardcoded keys leak through version control history.",
            fix_summary="Loaded API_KEY from environment variables.",
            original_code="API_KEY = 'AKIAIOSFODNN7EXAMPLE12345'",
            corrected_code="import os\nAPI_KEY = os.environ.get('API_KEY', '')",
            best_practice="Store credentials in a secret manager or environment variables.",
            references=["owasp_secrets_cheatsheet.txt"],
            verified=True,
            verification_note="Passed Python AST syntax check and secret scanner re-scan.",
            confidence=0.94,
        ),
    ]

    health = CodeHealthScore(
        score=72,
        grade="C",
        breakdown_by_severity={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 0},
        penalty_details={"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4, "LOW": 1, "INFO": 0},
    )

    pr_summary = PRSummary(
        executive_overview="Found 4 findings including 1 Critical SQL Injection and 1 High Hardcoded Secret in service.py.",
        severity_breakdown={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 0},
        top_risks=[
            "SQL Injection (CWE-89) at line 4 allows unauthorized database access.",
            "Hardcoded Secret (CWE-798) at line 2 exposes AWS credentials.",
        ],
        prioritized_fixes=[
            PrioritizedFix(
                finding_id="SEC-001",
                title="SQL Injection",
                severity=SeverityLevel.CRITICAL,
                effort="Low",
                reason="Critical data exposure risk with a verified parameterized query fix.",
            ),
            PrioritizedFix(
                finding_id="SEC-002",
                title="Hardcoded Secret",
                severity=SeverityLevel.HIGH,
                effort="Low",
                reason="Credential exposure in source code.",
            ),
            PrioritizedFix(
                finding_id="CODE-001",
                title="Broad Exception Handling",
                severity=SeverityLevel.MEDIUM,
                effort="Low",
                reason="Improves error diagnosability.",
            ),
            PrioritizedFix(
                finding_id="CODE-002",
                title="Magic Number",
                severity=SeverityLevel.LOW,
                effort="Low",
                reason="Improves maintainability.",
            ),
        ],
        health_score=health,
        markdown="# PR Review Summary\nMock markdown.",
    )

    result = AnalysisResult(
        findings=findings,
        counts_by_severity={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 0},
        counts_by_agent={"code_analysis": 2, "security_analysis": 2},
        language="python",
        filename="service.py",
        run_status={"code_analysis": "SUCCESS", "security_analysis": "SUCCESS"},
        remediations=remediations,
        pr_summary=pr_summary,
        health_score=health,
    )
    return result, source_code


def test_generate_report_valid_pdf_and_expected_sections():
    """Verifies %PDF header, embedded chart image, footer chrome, and all 7 sections via pypdf."""
    result, source_code = _make_rich_result()
    pdf_bytes = generate_report(result, source_code, "service.py", "python")

    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 2000

    reader, text = _extract_all_text(pdf_bytes)
    assert len(reader.pages) >= 2

    # Cover Page & Footer Chrome
    assert "AI Code Review & Security Analysis Report" in text
    assert "service.py" in text
    assert "Python" in text
    assert "72 / 100" in text
    assert "Grade: C" in text
    assert "File: service.py" in text
    assert "Page 1" in text
    assert "Page 2" in text

    # Required Sections
    assert "1. Executive Overview" in text
    assert "1 Critical SQL Injection" in text
    assert "2. Severity Breakdown" in text
    assert "3. Findings Summary Table" in text
    assert "4. Detailed Findings" in text
    assert "5. Prioritized Remediation Roadmap" in text
    assert "6. Overall Code Quality Assessment" in text

    # Findings & OWASP & Remediation content
    assert "SEC-001" in text
    assert "A05:2025-Injection (CWE-89)" in text
    assert "VERIFIED FIX" in text
    assert "SELECT * FROM users WHERE id = ?" in text
    assert "owasp_sqli_cheatsheet.txt" in text

    # Roadmap tiers
    assert "Fix Now" in text
    assert "Next" in text
    assert "Later" in text

    # Assessment subsections
    assert "Strengths" in text
    assert "Weaknesses" in text
    assert "Health Score Reasoning" in text

    # Embedded Matplotlib chart image present in PDF pages
    total_images = sum(len(page.images) for page in reader.pages)
    assert total_images >= 1


def test_generate_report_zero_findings():
    """Handles zero findings gracefully with 100/A score and clean report sections."""
    clean_code = "def add(a: int, b: int) -> int:\n    return a + b\n"
    result = AnalysisResult(
        findings=[],
        counts_by_severity={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        counts_by_agent={"code_analysis": 0, "security_analysis": 0},
        language="python",
        filename="clean_math.py",
        run_status={"code_analysis": "SUCCESS", "security_analysis": "SUCCESS"},
        remediations=[],
        pr_summary=None,
        health_score=None,
    )

    pdf_bytes = generate_report(result, clean_code, "clean_math.py", "python")
    assert pdf_bytes.startswith(b"%PDF")

    reader, text = _extract_all_text(pdf_bytes)
    assert len(reader.pages) >= 2
    assert "clean_math.py" in text
    assert "100 / 100" in text
    assert "Grade: A" in text
    assert "1. Executive Overview" in text
    assert "2. Severity Breakdown" in text
    assert "3. Findings Summary Table" in text
    assert "4. Detailed Findings" in text
    assert "5. Prioritized Remediation Roadmap" in text
    assert "6. Overall Code Quality Assessment" in text
    assert "Zero findings detected" in text or "zero detected findings" in text.lower()
    assert sum(len(page.images) for page in reader.pages) >= 1


def test_generate_report_large_findings_pagination():
    """Handles 100+ findings cleanly with multi-page pagination and no LayoutError."""
    severities = [
        SeverityLevel.CRITICAL,
        SeverityLevel.HIGH,
        SeverityLevel.MEDIUM,
        SeverityLevel.LOW,
        SeverityLevel.INFO,
    ]
    findings = []
    remediations = []
    source_lines = []

    for i in range(1, 116):
        sev = severities[(i - 1) % len(severities)]
        fid = f"F-{i:03d}"
        code_line = f"val_{i} = process_item_{i}(user_input_{i})"
        source_lines.append(code_line)
        findings.append(
            Finding(
                id=fid,
                title=f"Synthetic Issue #{i}",
                category="Security Vulnerability" if sev in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) else "Code Smell",
                agent="security_analysis" if sev in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) else "code_analysis",
                severity=sev,
                severity_score=9.0 if sev == SeverityLevel.CRITICAL else 5.0,
                file="massive_module.py",
                line_start=i,
                line_end=i,
                code_snippet=code_line,
                explanation=f"Detailed explanation for synthetic finding {fid} on line {i}.",
                suggestion=f"Refactor line {i} safely.",
                confidence=0.9,
                owasp_category=OWASPCategory.A05 if sev == SeverityLevel.CRITICAL else None,
                cwe_id="CWE-89" if sev == SeverityLevel.CRITICAL else None,
            )
        )
        # Provide remediation for half the findings; leave the other half missing
        if i % 2 == 0:
            remediations.append(
                RemediationResult(
                    finding_id=fid,
                    explanation=f"Why {fid} is risky.",
                    fix_summary=f"Sanitized input for {fid}.",
                    original_code=code_line,
                    corrected_code=f"val_{i} = safe_process_item_{i}(sanitize(user_input_{i}))",
                    best_practice="Validate and sanitize all untrusted inputs.",
                    references=["A05_injection.md"],
                    verified=(i % 4 == 0),
                    verification_note="Verified automatically." if i % 4 == 0 else "Manual review required.",
                    confidence=0.85,
                )
            )

    result = AnalysisResult(
        findings=findings,
        counts_by_severity={"CRITICAL": 23, "HIGH": 23, "MEDIUM": 23, "LOW": 23, "INFO": 23},
        counts_by_agent={"code_analysis": 69, "security_analysis": 46},
        language="python",
        filename="massive_module.py",
        remediations=remediations,
    )

    pdf_bytes = generate_report(result, "\n".join(source_lines), "massive_module.py", "python")
    assert pdf_bytes.startswith(b"%PDF")

    reader, text = _extract_all_text(pdf_bytes)
    assert len(reader.pages) >= 6
    assert "F-001" in text
    assert "F-115" in text
    assert "115" in text
    assert "5. Prioritized Remediation Roadmap" in text
    assert "6. Overall Code Quality Assessment" in text


def test_generate_report_special_characters_and_very_long_lines():
    """Handles XML chars (<, >, &, quotes), Latin-1 accents, emojis, and 300+ char code lines."""
    long_token = "A" * 320
    tricky_code = (
        f"html_out = '<script>alert(\"xss & \\'cafe\\'\")</script>'  # café naïve — test… 🛡️\n"
        f"very_long_var = '{long_token}'\n"
    )

    finding = Finding(
        id="SEC-XSS",
        title="Reflected XSS <img src=x onerror=alert(1)> & 'Quotes' — café 🛡️",
        category="Security & Input Validation <A05>",
        agent="security_analysis",
        severity=SeverityLevel.HIGH,
        severity_score=7.8,
        file="xss_&_café_test.py",
        line_start=1,
        line_end=2,
        code_snippet=tricky_code,
        explanation="Unescaped HTML output with <script> & \"quotes\" — leads to XSS in café portal…",
        suggestion="Use html.escape(value, quote=True) before rendering.",
        confidence=0.91,
        owasp_category=OWASPCategory.A05,
        cwe_id="CWE-79",
    )

    remediation = RemediationResult(
        finding_id="SEC-XSS",
        explanation="Browser executes raw <script> tags.",
        fix_summary="Escape '<', '>', '&', and quotes with html.escape().",
        original_code=tricky_code,
        corrected_code=f"import html\nhtml_out = html.escape('<script>alert(\"xss\")</script>')\nvery_long_var = '{'B' * 280}'",
        best_practice="Context-aware HTML encoding prevents CWE-79.",
        references=["A05_injection.md"],
        verified=True,
        verification_note="Verified — zero regressions ✅",
        confidence=0.92,
    )

    result = AnalysisResult(
        findings=[finding],
        counts_by_severity={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        counts_by_agent={"code_analysis": 0, "security_analysis": 1},
        language="python",
        filename="xss_&_café_test.py",
        remediations=[remediation],
    )

    pdf_bytes = generate_report(result, tricky_code, "xss_&_café_test.py", "python")
    assert pdf_bytes.startswith(b"%PDF")

    reader, text = _extract_all_text(pdf_bytes)
    assert len(reader.pages) >= 2
    assert "SEC-XSS" in text
    assert "<script>" in text
    assert "café" in text
    assert "html.escape" in text


def test_generate_report_missing_remediation_and_dict_input():
    """Accepts serialized dict (Streamlit session_state) and missing remediation cleanly."""
    source_code = "def risky(cmd):\n    eval(cmd)\n"
    result_dict = {
        "findings": [
            {
                "id": "SEC-099",
                "title": "Dynamic Code Execution",
                "category": "Security Vulnerability",
                "agent": "security_analysis",
                "severity": "CRITICAL",
                "severity_score": 9.5,
                "file": "dynamic.py",
                "line_start": 2,
                "line_end": 2,
                "code_snippet": "",  # forces fallback extraction from source_code
                "explanation": "Calling eval() on untrusted input allows arbitrary code execution.",
                "suggestion": "Use ast.literal_eval() for safe literal parsing.",
                "confidence": 0.95,
                "owasp_category": "OWASPCategory.A05",
                "cwe_id": "CWE-95",
            }
        ],
        "counts_by_severity": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "counts_by_agent": {"code_analysis": 0, "security_analysis": 1},
        "language": "python",
        "filename": "dynamic.py",
        "remediations": [],
        "pr_summary": None,
        "health_score": None,
    }

    pdf_bytes = generate_report(result_dict, source_code, "dynamic.py", "python")
    assert pdf_bytes.startswith(b"%PDF")

    _, text = _extract_all_text(pdf_bytes)
    assert "SEC-099" in text
    assert "eval(cmd)" in text
    assert "No automated remediation generated" in text
    assert "ast.literal_eval()" in text
    assert "A05:2025-Injection (CWE-95)" in text


def test_generate_report_e2e_with_orchestrator_python_sample():
    """End-to-end test: runs orchestrator.analyze() on planted_security.py and renders PDF."""
    sample_path = Path(__file__).resolve().parent / "samples" / "python" / "planted_security.py"
    code = sample_path.read_text(encoding="utf-8")

    analysis_result = analyze(code, language="python", filename="planted_security.py")
    pdf_bytes = generate_report(analysis_result, code, "planted_security.py", "python")

    assert pdf_bytes.startswith(b"%PDF")
    reader, text = _extract_all_text(pdf_bytes)
    assert len(reader.pages) >= 3
    assert "planted_security.py" in text
    assert "39 / 100" in text
    assert "Grade: F" in text
    assert "SQL Injection" in text
    assert "Fix Now" in text
    assert "6. Overall Code Quality Assessment" in text

