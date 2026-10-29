"""
Unit tests for Multi-Agent Orchestrator (Milestone 2 Step 3).

Verifies:
1. Parallel execution returns merged and correctly sorted findings (severity_score descending).
2. Deduplication properly merges overlapping findings of the same type, preserving the higher severity.
3. Fault tolerance: one agent failing or throwing an exception does not crash the pipeline and returns the other agent's findings.
4. Benchmark evaluation test asserting overall F1 score >= 0.70.
"""

from unittest.mock import MagicMock
import pytest
import time

from agents.orchestrator import analyze, deduplicate_findings
from app.schemas import AnalysisResult, Finding, OWASPCategory, SeverityLevel
from tests.evaluate import run_evaluation


def test_parallel_run_returns_merged_and_sorted_findings():
    """
    Checks that analyze() runs both agents in parallel, merges findings,
    sorts findings by severity_score descending, and reports per-agent runtimes.
    """
    code = """
import os
import hashlib

def run_ops(cmd, token, a, b, c, d, e, f):
    # Command injection (Security)
    os.system("ping -c 1 " + cmd)
    # Weak hash (Security)
    hashlib.md5(token.encode()).hexdigest()
    # Too many parameters & Bare except (Quality)
    try:
        pass
    except:
        pass
"""
    result: AnalysisResult = analyze(code, language="python", filename="test_parallel.py")

    assert isinstance(result, AnalysisResult)
    assert len(result.findings) >= 3
    assert result.run_status.get("code_analysis") == "SUCCESS"
    assert result.run_status.get("security_analysis") == "SUCCESS"

    # Verify per-agent runtime tracking
    assert "code_analysis" in result.per_agent_runtime
    assert "security_analysis" in result.per_agent_runtime
    assert result.per_agent_runtime["code_analysis"] >= 0.0
    assert result.per_agent_runtime["security_analysis"] >= 0.0

    # Verify findings are sorted by severity_score descending
    scores = [f.severity_score for f in result.findings]
    assert scores == sorted(scores, reverse=True), f"Findings not sorted by severity_score descending: {scores}"

    # Verify both agents contributed
    agents_represented = {f.agent for f in result.findings}
    assert "code_analysis" in agents_represented
    assert "security_analysis" in agents_represented


def test_deduplicate_findings_keeps_higher_severity():
    """
    Verifies that deduplicate_findings keeps the higher severity finding
    when two findings from the same file overlap on lines and share the same category/type.
    """
    f_low = Finding(
        id="LOW-001",
        title="SQL Injection",
        category="Security Vulnerability",
        agent="heuristic_scanner",
        severity=SeverityLevel.LOW,
        severity_score=3.0,
        file="dao.py",
        line_start=10,
        line_end=15,
        code_snippet="cursor.execute(query)",
        explanation="Possible SQL issue",
        confidence=0.50,
        cwe_id="CWE-89",
    )
    f_critical = Finding(
        id="CRIT-001",
        title="SQL Injection",
        category="Security Vulnerability",
        agent="taint_scanner",
        severity=SeverityLevel.CRITICAL,
        severity_score=9.8,
        file="dao.py",
        line_start=12,
        line_end=14,
        code_snippet="cursor.execute(query)",
        explanation="Direct user-controlled SQL injection verified",
        confidence=0.95,
        cwe_id="CWE-89",
    )

    # Candidate with higher severity presented second
    merged1 = deduplicate_findings([f_low, f_critical])
    assert len(merged1) == 1
    assert merged1[0].id == "CRIT-001"
    assert merged1[0].severity == SeverityLevel.CRITICAL

    # Candidate with higher severity presented first
    merged2 = deduplicate_findings([f_critical, f_low])
    assert len(merged2) == 1
    assert merged2[0].id == "CRIT-001"
    assert merged2[0].severity == SeverityLevel.CRITICAL


def test_fault_isolation_when_one_agent_fails():
    """
    Verifies that if CodeAnalysisAgent raises a fatal runtime exception,
    the orchestrator isolates the failure, records it in run_status,
    and still returns the findings from SecurityAgent.
    """
    mock_code_agent = MagicMock()
    mock_code_agent.run.side_effect = RuntimeError("Simulated AST parser memory overflow")

    vulnerable_code = """
import os
os.system("cat /etc/passwd")
"""
    result = analyze(
        vulnerable_code,
        language="python",
        filename="fault_tolerance.py",
        code_agent=mock_code_agent
    )

    # Code agent should be flagged as ERROR in run_status
    assert "ERROR" in result.run_status["code_analysis"]
    assert "Simulated AST parser memory overflow" in result.run_status["code_analysis"]

    # Security agent should have succeeded
    assert result.run_status["security_analysis"] == "SUCCESS"

    # Security findings must still be returned
    assert len(result.findings) >= 1
    assert any(f.cwe_id == "CWE-78" for f in result.findings)


def test_fault_isolation_when_agent_times_out():
    """
    Verifies that if an agent exceeds the execution timeout,
    the orchestrator records a TIMEOUT in run_status without crashing.
    """
    mock_slow_agent = MagicMock()

    def slow_run(*args, **kwargs):
        time.sleep(0.3)
        return []

    mock_slow_agent.run.side_effect = slow_run

    code = "x = 1"
    result = analyze(
        code,
        language="python",
        filename="timeout_test.py",
        timeout=0.05,
        code_agent=mock_slow_agent
    )

    assert "TIMEOUT" in result.run_status["code_analysis"]
    assert result.run_status["security_analysis"] == "SUCCESS"


def test_benchmark_overall_f1_score_exceeds_threshold():
    """
    Verifies that the overall multi-agent system achieves an F1 score >= 0.70
    across all Python and Java evaluation samples in tests/samples/.
    """
    evaluation_results = run_evaluation()
    overall = evaluation_results.get("OVERALL SYSTEM")
    assert overall is not None, "Evaluation results missing 'OVERALL SYSTEM' entry"

    overall_f1 = overall["f1"]
    precision = overall["precision"]
    recall = overall["recall"]

    print(f"\n[Test Benchmark] Overall F1: {overall_f1:.4f} (Precision: {precision:.4f}, Recall: {recall:.4f})")
    assert overall_f1 >= 0.70, (
        f"Overall F1 score {overall_f1:.4f} is below required threshold of 0.70!\n"
        f"False Positives: {[f.title for f in overall['false_positives']]}\n"
        f"False Negatives: {[e['description'] for e in overall['false_negatives']]}"
    )
