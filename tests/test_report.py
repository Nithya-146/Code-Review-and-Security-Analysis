"""
Unit tests for Report Generation Module (app/report.py).

Verifies:
1. Risk rating calculation rules (Critical, High, Medium, Low, No issues found).
2. Top 5 ordering logic (highest-severity first, top 5 cap).
3. Empty findings handling across all report functions.
4. Markdown and self-contained HTML export generation.
"""

import pytest
from app.report import (
    calculate_risk_rating,
    get_top_findings,
    get_security_summary,
    get_quality_summary,
    get_recommended_steps,
    build_report_data,
    generate_markdown_report,
    generate_html_report,
)
from app.schemas import Finding, OWASPCategory, SeverityLevel, AnalysisResult


# ── Fixtures ─────────────────────────────────────────────────────────────────

def make_finding(
    id: str = "F-001",
    title: str = "Test Finding",
    severity: SeverityLevel = SeverityLevel.HIGH,
    score: float = 7.5,
    line: int = 10,
    agent: str = "security_analysis",
    owasp: OWASPCategory = OWASPCategory.A05,
    cwe: str = "CWE-89",
    suggestion: str = "Fix this issue immediately.",
    evidence: str = "[test.md]: Evidence text",
) -> Finding:
    """Helper factory for Finding instances."""
    return Finding(
        id=id,
        title=title,
        category="Security Vulnerability",
        agent=agent,
        severity=severity,
        severity_score=score,
        file="sample.py",
        line_start=line,
        line_end=line,
        explanation="Test explanation.",
        suggestion=suggestion,
        confidence=0.9,
        source="rule",
        owasp_category=owasp,
        cwe_id=cwe,
        evidence=evidence,
    )


# ── Test 1: Risk Rating Rules ────────────────────────────────────────────────

def test_risk_rating_critical_when_critical_exists():
    """Critical rating if any Critical finding is present."""
    findings = [
        make_finding(id="1", severity=SeverityLevel.LOW),
        make_finding(id="2", severity=SeverityLevel.CRITICAL),
        make_finding(id="3", severity=SeverityLevel.HIGH),
    ]
    level, reason, color = calculate_risk_rating(findings)
    assert level == "Critical"
    assert "critical" in reason.lower()
    assert color == "#EF4444"


def test_risk_rating_high_when_no_critical():
    """High rating if High exists and no Critical."""
    findings = [
        make_finding(id="1", severity=SeverityLevel.LOW),
        make_finding(id="2", severity=SeverityLevel.HIGH),
        make_finding(id="3", severity=SeverityLevel.MEDIUM),
    ]
    level, reason, color = calculate_risk_rating(findings)
    assert level == "High"
    assert "high-severity" in reason.lower()
    assert color == "#F97316"


def test_risk_rating_medium_when_no_critical_or_high():
    """Medium rating if Medium exists and no Critical or High."""
    findings = [
        make_finding(id="1", severity=SeverityLevel.LOW),
        make_finding(id="2", severity=SeverityLevel.MEDIUM),
    ]
    level, reason, color = calculate_risk_rating(findings)
    assert level == "Medium"
    assert "medium-severity" in reason.lower()
    assert color == "#EAB308"


def test_risk_rating_low_when_only_low_or_info():
    """Low rating when only Low or Info findings exist."""
    findings = [
        make_finding(id="1", severity=SeverityLevel.LOW),
        make_finding(id="2", severity=SeverityLevel.INFO),
    ]
    level, reason, color = calculate_risk_rating(findings)
    assert level == "Low"
    assert "low-severity" in reason.lower()
    assert color == "#3B82F6"


def test_risk_rating_empty_case():
    """'No issues found' when findings list is empty."""
    level, reason, color = calculate_risk_rating([])
    assert level == "No issues found"
    assert "no security or code quality issues" in reason.lower()
    assert color == "#10B981"


# ── Test 2: Top 5 Ordering ───────────────────────────────────────────────────

def test_top_5_ordering_by_severity_and_score():
    """
    Verifies top findings are ordered by severity tier first, then score,
    and returns at most 5 items.
    """
    findings = [
        make_finding(id="f_low", title="Low Issue", severity=SeverityLevel.LOW, score=3.0, line=5),
        make_finding(id="f_med", title="Medium Issue", severity=SeverityLevel.MEDIUM, score=5.5, line=10),
        make_finding(id="f_crit_1", title="Critical A", severity=SeverityLevel.CRITICAL, score=9.8, line=15),
        make_finding(id="f_high_1", title="High A", severity=SeverityLevel.HIGH, score=8.0, line=20),
        make_finding(id="f_crit_2", title="Critical B", severity=SeverityLevel.CRITICAL, score=9.0, line=25),
        make_finding(id="f_high_2", title="High B", severity=SeverityLevel.HIGH, score=7.5, line=30),
        make_finding(id="f_info", title="Info Note", severity=SeverityLevel.INFO, score=1.0, line=35),
    ]

    top_5 = get_top_findings(findings, limit=5)
    assert len(top_5) == 5

    # Order must be: Critical A (9.8), Critical B (9.0), High A (8.0), High B (7.5), Medium (5.5)
    expected_ids = ["f_crit_1", "f_crit_2", "f_high_1", "f_high_2", "f_med"]
    actual_ids = [f.id if hasattr(f, "id") else f["id"] for f in top_5]
    assert actual_ids == expected_ids


def test_top_5_fewer_than_5_items():
    """Returns all items if fewer than 5 exist."""
    findings = [
        make_finding(id="1", severity=SeverityLevel.HIGH),
        make_finding(id="2", severity=SeverityLevel.MEDIUM),
    ]
    top = get_top_findings(findings, limit=5)
    assert len(top) == 2


# ── Test 3: Empty Case Handling ──────────────────────────────────────────────

def test_empty_findings_full_report():
    """Verifies that an empty AnalysisResult builds a clean, complete report."""
    empty_result = AnalysisResult(
        findings=[],
        counts_by_severity={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        counts_by_agent={},
        per_agent_runtime={},
        language="python",
        filename="clean.py",
        run_status={"code_analysis": "SUCCESS", "security_analysis": "SUCCESS"},
    )

    data = build_report_data(empty_result, lines_of_code=42)
    assert data["risk_level"] == "No issues found"
    assert data["total_findings"] == 0
    assert len(data["top_5"]) == 0
    assert len(data["security_summary"]) == 0
    assert len(data["quality_summary"]) == 0
    assert "clean" in data["recommended_steps"][0].lower()

    # Markdown export must succeed and contain expected clean text
    md = generate_markdown_report(data)
    assert "# AI Code Review & Security Analysis Report" in md
    assert "clean.py" in md
    assert "NO ISSUES FOUND" in md

    # HTML export must succeed and be self-contained
    html_out = generate_html_report(data)
    assert "<!DOCTYPE html>" in html_out
    assert "clean.py" in html_out
    assert "No issues found" in html_out
    assert "badge-CLEAN" in html_out


# ── Test 4: Summaries and Deduplicated Recommendations ────────────────────────

def test_security_and_quality_summaries():
    """Verifies OWASP and quality category aggregation."""
    findings = [
        make_finding(id="1", owasp=OWASPCategory.A05),
        make_finding(id="2", owasp=OWASPCategory.A05),
        make_finding(id="3", owasp=OWASPCategory.A07),
        Finding(
            id="q1",
            title="High Cyclomatic Complexity",
            category="Code Smell & Maintainability",
            agent="code_analysis",
            severity=SeverityLevel.MEDIUM,
            severity_score=6.0,
            file="sample.py",
            line_start=12,
            line_end=12,
            explanation="Complexity > 10",
            suggestion="Refactor method into smaller units.",
            evidence="Static AST Check: cyclomatic_complexity",
        ),
    ]

    sec_sum = get_security_summary(findings)
    assert sec_sum["A05:2025 Injection"] == 2
    assert sec_sum["A07:2025 Authentication Failures"] == 1

    qual_sum = get_quality_summary(findings)
    assert qual_sum["Cyclomatic Complexity"] == 1


def test_recommended_steps_deduplication():
    """Verifies that suggestions are deduplicated while preserving order."""
    findings = [
        make_finding(id="1", severity=SeverityLevel.CRITICAL, suggestion="Use parameterized SQL."),
        make_finding(id="2", severity=SeverityLevel.HIGH, suggestion="Use parameterized SQL."),
        make_finding(id="3", severity=SeverityLevel.MEDIUM, suggestion="Sanitize user inputs."),
    ]
    steps = get_recommended_steps(findings, max_steps=5)
    assert len(steps) == 2
    assert steps[0] == "Use parameterized SQL."
    assert steps[1] == "Sanitize user inputs."
