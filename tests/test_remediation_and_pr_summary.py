"""
Comprehensive Unit Tests for Remediation Agent and PR Summary Agent (Milestone 3 Step 1).

Verifies:
1. Remediation for Python and Java:
   - SQL Injection (verified=True, syntax passes, diff generated)
   - Hardcoded Secret (verified=True, syntax passes, diff generated)
   - Code Smell - Broad Exception (verified=True, syntax passes, diff generated)
2. Remediation Verification:
   - Unverified finding handling (verified=False with descriptive note)
   - Fault tolerance (one bad finding does not crash the agent or pipeline)
3. PR Summary Agent:
   - Deterministic health score calculation: clean file (100/A), critical findings (low/F)
   - Exact grade boundaries (A, B, C, D, F) and diminishing-returns caps
   - Prioritization ordering: highest severity first, easiest fix first within tier
   - Full PR-style markdown generation containing all required sections
4. Orchestrator End-to-End Integration:
   - Pipeline execution on tests/samples/python/planted_security.py
   - Pipeline execution on tests/samples/java/PlantedSecurity.java
"""

from pathlib import Path
import pytest

from agents.orchestrator import analyze
from agents.remediation_agent import RemediationAgent
from agents.pr_summary_agent import PRSummaryAgent
from agents.security import SecurityAgent
from agents.code_analysis import CodeAnalysisAgent
from app.java_parser import validate_java
from app.python_parser import validate_python
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

SAMPLE_DIR = Path(__file__).resolve().parent / "samples"


# =============================================================================
# 1. Python Remediation Tests
# =============================================================================

def test_remediate_python_sqli():
    """Verifies that Python SQL injection is remediated, syntax-checked, and verified."""
    code = """import sqlite3

def get_user(conn, user_id):
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()
"""
    sec_agent = SecurityAgent()
    findings = sec_agent.run(code, language="python", filename="test_sqli.py")
    sqli_findings = [f for f in findings if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) >= 1

    rem_agent = RemediationAgent()
    results = rem_agent.remediate(code, language="python", findings=sqli_findings, filename="test_sqli.py")
    assert len(results) >= 1
    rem = results[0]

    assert rem.original_code != rem.corrected_code
    assert "?" in rem.corrected_code
    assert rem.verified is True
    assert "Verified" in rem.verification_note
    assert rem.confidence >= 0.90

    # Ensure candidate code passes syntax validation
    fix_span = rem_agent._generate_fix(sqli_findings[0], code, "python")[5]
    start_line = fix_span[0] if fix_span else sqli_findings[0].line_start
    candidate = rem_agent._build_candidate_code(
        code,
        start_line=start_line,
        end_line=sqli_findings[0].line_end,
        replacement_snippet=rem.corrected_code,
        language="python",
    )
    val = validate_python(candidate)
    assert val["is_valid"] is True


def test_remediate_python_hardcoded_secret():
    """Verifies that Python hardcoded secret is remediated with os.environ and verified."""
    code = """API_KEY = "AKIAIOSFODNN7EXAMPLE12345"
"""
    sec_agent = SecurityAgent()
    findings = sec_agent.run(code, language="python", filename="test_secret.py")
    secret_findings = [f for f in findings if f.cwe_id == "CWE-798"]
    assert len(secret_findings) >= 1

    rem_agent = RemediationAgent()
    results = rem_agent.remediate(code, language="python", findings=secret_findings, filename="test_secret.py")
    assert len(results) >= 1
    rem = results[0]

    assert rem.original_code != rem.corrected_code
    assert "os.environ.get" in rem.corrected_code
    assert rem.verified is True
    assert "Verified" in rem.verification_note

    candidate = rem_agent._build_candidate_code(
        code,
        start_line=secret_findings[0].line_start,
        end_line=secret_findings[0].line_end,
        replacement_snippet=rem.corrected_code,
        language="python",
    )
    val = validate_python(candidate)
    assert val["is_valid"] is True


def test_remediate_python_code_smell():
    """Verifies that Python broad exception smell is narrowed, syntax-checked, and verified."""
    code = """def calculate():
    try:
        val = int("abc")
    except:
        val = 0
    return val
"""
    code_agent = CodeAnalysisAgent()
    findings = code_agent.run(code, language="python", filename="test_smell.py")
    smell_findings = [f for f in findings if "except" in f.title.lower()]
    assert len(smell_findings) >= 1

    rem_agent = RemediationAgent()
    results = rem_agent.remediate(code, language="python", findings=smell_findings, filename="test_smell.py")
    assert len(results) >= 1
    rem = results[0]

    assert rem.original_code != rem.corrected_code
    assert "except (ValueError" in rem.corrected_code
    assert rem.verified is True
    assert "Verified" in rem.verification_note

    candidate = rem_agent._build_candidate_code(
        code,
        start_line=smell_findings[0].line_start,
        end_line=smell_findings[0].line_end,
        replacement_snippet=rem.corrected_code,
        language="python",
    )
    val = validate_python(candidate)
    assert val["is_valid"] is True


# =============================================================================
# 2. Java Remediation Tests
# =============================================================================

def test_remediate_java_sqli():
    """Verifies that Java SQL injection is remediated with PreparedStatement and verified."""
    code = """package samples;
import java.sql.Statement;
import java.sql.ResultSet;

public class UserDAO {
    public void queryUser(Statement stmt, String userId) throws Exception {
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = '" + userId + "'");
    }
}
"""
    sec_agent = SecurityAgent()
    findings = sec_agent.run(code, language="java", filename="UserDAO.java")
    sqli_findings = [f for f in findings if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) >= 1

    rem_agent = RemediationAgent()
    results = rem_agent.remediate(code, language="java", findings=sqli_findings, filename="UserDAO.java")
    assert len(results) >= 1
    rem = results[0]

    assert rem.original_code != rem.corrected_code
    assert "PreparedStatement" in rem.corrected_code
    assert rem.verified is True
    assert "Verified" in rem.verification_note

    candidate = rem_agent._build_candidate_code(
        code,
        start_line=sqli_findings[0].line_start,
        end_line=sqli_findings[0].line_end,
        replacement_snippet=rem.corrected_code,
        language="java",
    )
    val = validate_java(candidate)
    assert val["is_valid"] is True


def test_remediate_java_hardcoded_secret():
    """Verifies that Java hardcoded secret is remediated with System.getenv and verified."""
    code = """package samples;

public class Config {
    private String dbPassword = "SecretAdminPassword987!";
}
"""
    sec_agent = SecurityAgent()
    findings = sec_agent.run(code, language="java", filename="Config.java")
    secret_findings = [f for f in findings if f.cwe_id == "CWE-798"]
    assert len(secret_findings) >= 1

    rem_agent = RemediationAgent()
    results = rem_agent.remediate(code, language="java", findings=secret_findings, filename="Config.java")
    assert len(results) >= 1
    rem = results[0]

    assert rem.original_code != rem.corrected_code
    assert "System.getenv" in rem.corrected_code
    assert rem.verified is True
    assert "Verified" in rem.verification_note

    candidate = rem_agent._build_candidate_code(
        code,
        start_line=secret_findings[0].line_start,
        end_line=secret_findings[0].line_end,
        replacement_snippet=rem.corrected_code,
        language="java",
    )
    val = validate_java(candidate)
    assert val["is_valid"] is True


def test_remediate_java_code_smell():
    """Verifies that Java broad catch clause is narrowed and verified."""
    code = """package samples;

public class Worker {
    public void execute() {
        try {
            System.out.println("Processing");
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }
}
"""
    code_agent = CodeAnalysisAgent()
    findings = code_agent.run(code, language="java", filename="Worker.java")
    smell_findings = [f for f in findings if "catch" in f.title.lower()]
    assert len(smell_findings) >= 1

    rem_agent = RemediationAgent()
    results = rem_agent.remediate(code, language="java", findings=smell_findings, filename="Worker.java")
    assert len(results) >= 1
    rem = results[0]

    assert rem.original_code != rem.corrected_code
    assert "catch (IllegalArgumentException" in rem.corrected_code
    assert rem.verified is True
    assert "Verified" in rem.verification_note

    candidate = rem_agent._build_candidate_code(
        code,
        start_line=smell_findings[0].line_start,
        end_line=smell_findings[0].line_end,
        replacement_snippet=rem.corrected_code,
        language="java",
    )
    val = validate_java(candidate)
    assert val["is_valid"] is True


# =============================================================================
# 3. Verification Edge Cases & Fault Tolerance
# =============================================================================

def test_remediation_unverified_finding():
    """Verifies that an unsupported or unverified finding sets verified=False with note."""
    code = """x = 1
"""
    finding = Finding(
        id="CUSTOM-999",
        title="Custom Architectural Anomaly",
        category="Architecture",
        agent="code_analysis",
        severity=SeverityLevel.LOW,
        severity_score=2.0,
        file="test.py",
        line_start=1,
        line_end=1,
        code_snippet="x = 1",
        explanation="Architectural anomaly requires manual restructuring.",
        suggestion="Redesign module boundaries.",
        confidence=0.5,
    )

    rem_agent = RemediationAgent()
    results = rem_agent.remediate(code, language="python", findings=[finding], filename="test.py")
    assert len(results) == 1
    assert results[0].verified is False
    assert "Verification note" in results[0].verification_note or "Verification failed" in results[0].verification_note


def test_remediation_fault_isolation_on_bad_finding():
    """Verifies that a malformed finding does not crash the agent or disrupt other findings."""
    code = """API_KEY = "AKIAIOSFODNN7EXAMPLE12345"
"""
    good_finding = Finding(
        id="GOOD-001",
        title="Hardcoded Secret",
        category="Security Vulnerability",
        agent="security_analysis",
        severity=SeverityLevel.HIGH,
        severity_score=8.5,
        file="test.py",
        line_start=1,
        line_end=1,
        code_snippet='API_KEY = "AKIAIOSFODNN7EXAMPLE12345"',
        explanation="Hardcoded AWS secret key.",
        cwe_id="CWE-798",
    )
    bad_finding = Finding(
        id="BAD-999",
        title="Malformed Finding",
        category="Security Vulnerability",
        agent="security_analysis",
        severity=SeverityLevel.CRITICAL,
        severity_score=9.9,
        file="test.py",
        line_start=999999,  # Out-of-bounds line index
        line_end=999999,
        code_snippet=None,
        explanation="Simulated corrupted finding.",
    )

    rem_agent = RemediationAgent()
    # Process both findings together
    results = rem_agent.remediate(code, language="python", findings=[bad_finding, good_finding], filename="test.py")
    assert len(results) == 2

    # Verify that the bad finding was isolated with verified=False
    bad_result = next(r for r in results if r.finding_id == "BAD-999")
    assert bad_result.verified is False

    # Verify that the good finding succeeded despite the bad finding
    good_result = next(r for r in results if r.finding_id == "GOOD-001")
    assert good_result.verified is True


# =============================================================================
# 4. PR Summary Agent Tests
# =============================================================================

def test_pr_summary_health_score_clean_file():
    """Verifies deterministic health score for clean code (100 / Grade A)."""
    agent = PRSummaryAgent()
    health = agent.compute_health_score([])

    assert health.score == 100
    assert health.grade == "A"
    assert health.breakdown_by_severity[SeverityLevel.CRITICAL.value] == 0
    assert health.breakdown_by_severity[SeverityLevel.HIGH.value] == 0
    assert sum(health.penalty_details.values()) == 0


def test_pr_summary_health_score_critical_findings():
    """Verifies health score deduction and diminishing returns for critical findings."""
    agent = PRSummaryAgent()

    # 1 Critical finding: 100 - 15 = 85 (Grade B)
    f_crit = Finding(
        id="C-1",
        title="SQL Injection",
        category="Security",
        agent="security_analysis",
        severity=SeverityLevel.CRITICAL,
        severity_score=9.8,
        file="dao.py",
        line_start=1,
        line_end=1,
        explanation="SQL injection.",
    )
    h1 = agent.compute_health_score([f_crit])
    assert h1.score == 85
    assert h1.grade == "B"

    # 3 Critical findings: 100 - (3 * 15) = 55 (Grade F)
    findings_3_crit = [
        f_crit,
        f_crit.model_copy(update={"id": "C-2"}),
        f_crit.model_copy(update={"id": "C-3"}),
    ]
    h3 = agent.compute_health_score(findings_3_crit)
    assert h3.score == 55
    assert h3.grade == "F"

    # 5 Critical findings: Capped at 45 penalty points -> score remains 55 (diminishing returns)
    findings_5_crit = findings_3_crit + [
        f_crit.model_copy(update={"id": "C-4"}),
        f_crit.model_copy(update={"id": "C-5"}),
    ]
    h5 = agent.compute_health_score(findings_5_crit)
    assert h5.penalty_details[SeverityLevel.CRITICAL.value] == 45
    assert h5.score == 55
    assert h5.grade == "F"


def test_pr_summary_grade_boundaries():
    """Verifies deterministic grade boundaries across the entire 0-100 spectrum."""
    agent = PRSummaryAgent()

    def make_findings(crit=0, high=0, med=0, low=0):
        res = []
        for i in range(crit):
            res.append(Finding(id=f"c{i}", title="c", category="s", agent="sec", severity=SeverityLevel.CRITICAL, severity_score=9.0, file="f", line_start=1, line_end=1, explanation="e"))
        for i in range(high):
            res.append(Finding(id=f"h{i}", title="h", category="s", agent="sec", severity=SeverityLevel.HIGH, severity_score=7.0, file="f", line_start=1, line_end=1, explanation="e"))
        for i in range(med):
            res.append(Finding(id=f"m{i}", title="m", category="s", agent="sec", severity=SeverityLevel.MEDIUM, severity_score=5.0, file="f", line_start=1, line_end=1, explanation="e"))
        for i in range(low):
            res.append(Finding(id=f"l{i}", title="l", category="s", agent="sec", severity=SeverityLevel.LOW, severity_score=3.0, file="f", line_start=1, line_end=1, explanation="e"))
        return res

    # Score 100 -> A
    assert agent.compute_health_score(make_findings()).grade == "A"
    # Score 92 (1 high = -8) -> A
    assert agent.compute_health_score(make_findings(high=1)).grade == "A"
    # Score 84 (2 highs = -16) -> B
    assert agent.compute_health_score(make_findings(high=2)).grade == "B"
    # Score 76 (3 highs = -24) -> C
    assert agent.compute_health_score(make_findings(high=3)).grade == "C"
    # Score 68 (4 highs = -32) -> D
    assert agent.compute_health_score(make_findings(high=4)).grade == "D"
    # Score 53 (4 highs + 1 crit = -32 - 15 = -47) -> F
    assert agent.compute_health_score(make_findings(high=4, crit=1)).grade == "F"


def test_pr_summary_markdown_sections():
    """Verifies that generated PR markdown contains all required sections and formatting."""
    agent = PRSummaryAgent()
    finding = Finding(
        id="SEC-001",
        title="SQL Injection",
        category="Security Vulnerability",
        agent="security_analysis",
        severity=SeverityLevel.CRITICAL,
        severity_score=9.8,
        file="app.py",
        line_start=10,
        line_end=10,
        code_snippet='cursor.execute(f"SELECT * FROM users WHERE id = \'{user_id}\'")',
        explanation="Untrusted data concatenated into SQL query.",
        cwe_id="CWE-89",
    )
    rem = RemediationResult(
        finding_id="SEC-001",
        explanation="SQL injection flaw.",
        fix_summary="Parameterized query with ? placeholder.",
        original_code='cursor.execute(f"SELECT * FROM users WHERE id = \'{user_id}\'")',
        corrected_code='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        best_practice="Always use parameter binding.",
        references=["A05_injection.md"],
        verified=True,
        verification_note="Verified: Syntax check passed.",
        confidence=0.95,
    )

    summary = agent.summarize(findings=[finding], remediations=[rem], filename="app.py", language="python")
    md = summary.markdown

    assert "# Pull Request Security & Quality Review: `app.py`" in md
    assert "## Executive Summary" in md
    assert "## Code Health Score" in md
    assert "### Findings Breakdown by Severity" in md
    assert "## Prioritized Action Items" in md
    assert "## Remediation Details & Verified Diffs" in md
    assert "```diff" in md
    assert "- cursor.execute" in md
    assert "+ cursor.execute" in md
    assert "[x] Verified" in md


def test_pr_summary_prioritization_logic():
    """Verifies prioritization ordering: Severity descending, then Effort ascending."""
    agent = PRSummaryAgent()

    # Create findings with varying severity and effort
    f_crit_med = Finding(
        id="F-1",
        title="SQL Injection",
        category="Security",
        agent="sec",
        severity=SeverityLevel.CRITICAL,
        severity_score=9.8,
        file="a.py",
        line_start=1,
        line_end=1,
        explanation="e",
        cwe_id="CWE-89",
    )
    f_high_low = Finding(
        id="F-2",
        title="Hardcoded Secret",
        category="Security",
        agent="sec",
        severity=SeverityLevel.HIGH,
        severity_score=8.5,
        file="a.py",
        line_start=2,
        line_end=2,
        explanation="e",
        cwe_id="CWE-798",
    )
    f_med_low = Finding(
        id="F-3",
        title="Bare Except",
        category="Quality",
        agent="code",
        severity=SeverityLevel.MEDIUM,
        severity_score=5.0,
        file="a.py",
        line_start=3,
        line_end=3,
        explanation="e",
    )

    prioritized = agent.prioritize_fixes([f_med_low, f_high_low, f_crit_med], [])
    ids = [p.finding_id for p in prioritized]
    # Critical should be first, High second, Medium third
    assert ids == ["F-1", "F-2", "F-3"]
    assert prioritized[0].effort == "Medium"
    assert prioritized[1].effort == "Low"
    assert prioritized[2].effort == "Low"


# =============================================================================
# 5. Orchestrator End-to-End Integration Tests
# =============================================================================

def test_orchestrator_e2e_python_sample():
    """Verifies end-to-end pipeline on planted_security.py."""
    sample_file = SAMPLE_DIR / "python" / "planted_security.py"
    assert sample_file.exists(), f"Sample file not found: {sample_file}"
    code = sample_file.read_text(encoding="utf-8")

    result = analyze(code, language="python", filename="planted_security.py")

    assert isinstance(result, AnalysisResult)
    assert len(result.findings) >= 4
    assert len(result.remediations) >= 4
    assert result.pr_summary is not None
    assert result.health_score is not None

    # planted_security.py contains multiple critical/high security flaws
    assert result.health_score.score < 60
    assert result.health_score.grade == "F"

    # Verify that at least one remediation was verified
    verified_fixes = [r for r in result.remediations if r.verified]
    assert len(verified_fixes) >= 1
    assert "remediation_agent" in result.per_agent_runtime
    assert "pr_summary_agent" in result.per_agent_runtime


def test_orchestrator_e2e_java_sample():
    """Verifies end-to-end pipeline on PlantedSecurity.java."""
    sample_file = SAMPLE_DIR / "java" / "PlantedSecurity.java"
    assert sample_file.exists(), f"Sample file not found: {sample_file}"
    code = sample_file.read_text(encoding="utf-8")

    result = analyze(code, language="java", filename="PlantedSecurity.java")

    assert isinstance(result, AnalysisResult)
    assert len(result.findings) >= 4
    assert len(result.remediations) >= 4
    assert result.pr_summary is not None
    assert result.health_score is not None

    # PlantedSecurity.java contains multiple critical/high security flaws
    assert result.health_score.score < 60
    assert result.health_score.grade == "F"

    # Verify that at least one remediation was verified
    verified_fixes = [r for r in result.remediations if r.verified]
    assert len(verified_fixes) >= 1
    assert "remediation_agent" in result.per_agent_runtime
    assert "pr_summary_agent" in result.per_agent_runtime
