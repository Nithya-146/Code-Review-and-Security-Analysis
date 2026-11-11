"""
Unit Tests & Smoke Tests for UI Helper Module & Streamlit Portal (Milestone 3 Step 3).

Covers:
- Sorting (severity, line, confidence)
- Multi-criteria filtering (severity, agent, category, text search)
- Code Health Score color-coding & letter grade mapping (A-F)
- Severity breakdown counting & verified remediation counting
- Inline SVG visualizations & HTML-escaped vulnerable line viewer
- JSON & PR Markdown export helpers
- Input validation & sample loader utilities
- End-to-end Streamlit AppTest smoke test (gracefully skipped if AppTest or
  loopback event-loop sockets are unavailable in the execution environment)
"""

from pathlib import Path
import json
import threading
import pytest

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
from app.ui_components import (
    badge_html,
    build_code_viewer_html,
    build_health_gauge_svg,
    build_prioritized_fixes_table_html,
    build_severity_donut_svg,
    export_pr_markdown,
    export_results_json,
    extract_severity_str,
    filter_findings,
    get_health_grade,
    get_health_score_color,
    get_severity_counts,
    get_verified_remediation_counts,
    grounding_badge_html,
    load_sample_code,
    map_remediations_by_finding,
    sort_findings,
    validate_submission_input,
    verified_badge_html,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_finding(
    fid: str = "SEC-001",
    title: str = "SQL Injection",
    category: str = "Security Vulnerability",
    agent: str = "security_analysis",
    severity: SeverityLevel = SeverityLevel.CRITICAL,
    severity_score: float = 9.5,
    line_start: int = 10,
    line_end: int = 10,
    cwe_id: str = "CWE-89",
    confidence: float = 0.95,
    code_snippet: str = "cursor.execute(f'SELECT * FROM t WHERE id={uid}')",
    explanation: str = "Untrusted SQL formatting allows query injection.",
) -> Finding:
    return Finding(
        id=fid,
        title=title,
        category=category,
        agent=agent,
        severity=severity,
        severity_score=severity_score,
        file="sample.py",
        line_start=line_start,
        line_end=line_end,
        code_snippet=code_snippet,
        explanation=explanation,
        suggestion="Use parameterized queries.",
        confidence=confidence,
        source="rule",
        owasp_category=OWASPCategory.A05 if agent == "security_analysis" else None,
        cwe_id=cwe_id if agent == "security_analysis" else None,
    )


def _make_sample_analysis_result() -> AnalysisResult:
    findings = [
        _make_finding(
            "CODE-001",
            "Deep Nesting",
            "Code Smell",
            "code_analysis",
            SeverityLevel.LOW,
            2.5,
            40,
            50,
            confidence=0.8,
            code_snippet="if a:\n  if b:\n    if c:\n      pass",
            explanation="Nesting depth exceeds threshold.",
        ),
        _make_finding(
            "SEC-001",
            "SQL Injection",
            "Security Vulnerability",
            "security_analysis",
            SeverityLevel.CRITICAL,
            9.8,
            18,
            19,
            cwe_id="CWE-89",
            confidence=0.98,
            code_snippet="cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
            explanation="Untrusted SQL formatting allows query injection.",
        ),
        _make_finding(
            "SEC-002",
            "Weak Cryptography",
            "Security Vulnerability",
            "security_analysis",
            SeverityLevel.HIGH,
            7.5,
            29,
            30,
            cwe_id="CWE-327",
            confidence=0.90,
            code_snippet="hashlib.md5(token.encode()).hexdigest()",
            explanation="Deprecated MD5 hashing algorithm used.",
        ),
    ]
    rems = [
        RemediationResult(
            finding_id="SEC-001",
            explanation="Dynamic SQL interpolation enables injection.",
            fix_summary="Use parameterized placeholder '?'",
            original_code="cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
            corrected_code="cursor.execute('SELECT * FROM users WHERE id=?', (uid,))",
            best_practice="Always bind query parameters separately.",
            references=["A05_injection.md"],
            verified=True,
            verification_note="Verified: AST valid and no SQLi detected.",
            confidence=0.95,
        ),
        RemediationResult(
            finding_id="CODE-001",
            explanation="Excessive indentation harms readability.",
            fix_summary="Extract helper function or guard clause.",
            original_code="if a:\n  if b:\n    pass",
            corrected_code="if not (a and b):\n  return",
            best_practice="Prefer early returns over nested conditionals.",
            references=["clean_code.md"],
            verified=False,
            verification_note="Manual refactoring advised.",
            confidence=0.75,
        ),
    ]
    hs = CodeHealthScore(
        score=72,
        grade="C",
        breakdown_by_severity={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 1, "INFO": 0},
        penalty_details={"CRITICAL": 15, "HIGH": 8, "MEDIUM": 0, "LOW": 1, "INFO": 0},
    )
    pr = PRSummary(
        executive_overview="Review detected 3 issues including critical SQL injection.",
        severity_breakdown=hs.breakdown_by_severity,
        top_risks=["[CWE-89] SQL Injection: Untrusted SQL formatting."],
        prioritized_fixes=[
            PrioritizedFix(
                finding_id="SEC-001",
                title="SQL Injection",
                severity=SeverityLevel.CRITICAL,
                effort="Medium",
                reason="Highest impact exploitability.",
            )
        ],
        health_score=hs,
        markdown="# Pull Request Security & Quality Review: `sample.py`\n\n## Executive Summary\nTest overview.",
    )
    return AnalysisResult(
        findings=findings,
        counts_by_severity=hs.breakdown_by_severity,
        counts_by_agent={"security_analysis": 2, "code_analysis": 1},
        per_agent_runtime={"security_analysis": 0.12, "code_analysis": 0.05},
        language="python",
        filename="sample.py",
        run_status={"code_analysis": "SUCCESS", "security_analysis": "SUCCESS"},
        remediations=rems,
        pr_summary=pr,
        health_score=hs,
    )


def _asyncio_loopback_available(timeout_sec: float = 2.0) -> bool:
    """
    Probes whether asyncio.new_event_loop() succeeds cleanly within timeout_sec.
    Restricted Windows sandboxes can block internal socketpair self-pipe creation.
    """
    import asyncio

    result = {"ok": False}

    def _probe():
        try:
            loop = asyncio.new_event_loop()
            loop.close()
            result["ok"] = True
        except Exception:
            result["ok"] = False

    t = threading.Thread(target=_probe, daemon=True)
    t.start()
    t.join(timeout=timeout_sec)
    return result["ok"]


# ── Unit Tests: Sorting & Filtering ──────────────────────────────────────────

def test_sort_findings_by_severity_line_and_confidence():
    """Verifies sorting across all 3 supported keys and empty lists."""
    assert sort_findings([]) == []

    f_low = _make_finding("L1", severity=SeverityLevel.LOW, severity_score=2.0, line_start=5, confidence=0.99)
    f_crit_high_line = _make_finding("C2", severity=SeverityLevel.CRITICAL, severity_score=9.8, line_start=30, confidence=0.80)
    f_crit_early_line = _make_finding("C1", severity=SeverityLevel.CRITICAL, severity_score=9.8, line_start=12, confidence=0.90)
    f_high = _make_finding("H1", severity=SeverityLevel.HIGH, severity_score=7.5, line_start=20, confidence=0.70)

    by_sev = sort_findings([f_low, f_crit_high_line, f_high, f_crit_early_line], sort_by="severity")
    assert [f.id for f in by_sev] == ["C1", "C2", "H1", "L1"]

    by_line = sort_findings([f_low, f_crit_high_line, f_high, f_crit_early_line], sort_by="line")
    assert [f.id for f in by_line] == ["L1", "C1", "H1", "C2"]

    by_conf = sort_findings([f_low, f_crit_high_line, f_high, f_crit_early_line], sort_by="confidence")
    assert [f.id for f in by_conf] == ["L1", "C1", "C2", "H1"]


def test_filter_findings_multi_criteria_and_search():
    """Verifies filtering by severity, agent, category, and case-insensitive text search."""
    items = _make_sample_analysis_result().findings

    assert filter_findings([]) == []
    assert len(filter_findings(items)) == 3
    assert filter_findings(items, severities=[]) == []

    # Severity filter
    only_crit = filter_findings(items, severities=["CRITICAL"])
    assert [f.id for f in only_crit] == ["SEC-001"]

    # Agent filter
    only_code = filter_findings(items, agents=["code_analysis"])
    assert [f.id for f in only_code] == ["CODE-001"]

    # Category filter
    only_sec_cat = filter_findings(items, categories=["Security Vulnerability"])
    assert len(only_sec_cat) == 2

    # Text search matching CWE, title, or snippet
    cwe_hits = filter_findings(items, search_text="cwe-327")
    assert [f.id for f in cwe_hits] == ["SEC-002"]

    snippet_hits = filter_findings(items, search_text="SELECT * FROM")
    assert [f.id for f in snippet_hits] == ["SEC-001"]

    # Combined filters
    combined = filter_findings(
        items,
        severities=["CRITICAL", "HIGH"],
        agents=["security_analysis"],
        search_text="injection",
    )
    assert [f.id for f in combined] == ["SEC-001"]


# ── Unit Tests: Health Color, Grade, Counts, Mapping ─────────────────────────

def test_health_score_color_and_grade_mapping():
    """Checks A-F thresholds and dark-theme readable hex colors from green to red."""
    assert get_health_grade(100) == "A"
    assert get_health_grade(90) == "A"
    assert get_health_score_color(95) == "#10B981"

    assert get_health_grade(89) == "B"
    assert get_health_grade(80) == "B"
    assert get_health_score_color(84) == "#22C55E"

    assert get_health_grade(79) == "C"
    assert get_health_grade(70) == "C"
    assert get_health_score_color(72) == "#EAB308"

    assert get_health_grade(69) == "D"
    assert get_health_grade(60) == "D"
    assert get_health_score_color(63) == "#F97316"

    assert get_health_grade(59) == "F"
    assert get_health_grade(0) == "F"
    assert get_health_score_color(20) == "#EF4444"


def test_severity_counts_and_remediation_helpers():
    """Verifies severity counting, string extraction, and verified remediation counts."""
    assert extract_severity_str({"severity": "SeverityLevel.HIGH"}) == "HIGH"
    assert get_severity_counts([]) == {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "TOTAL": 0
    }

    res = _make_sample_analysis_result()
    counts = get_severity_counts(res.findings)
    assert counts["CRITICAL"] == 1
    assert counts["HIGH"] == 1
    assert counts["LOW"] == 1
    assert counts["TOTAL"] == 3

    verified_cnt, total_cnt = get_verified_remediation_counts(res.remediations)
    assert (verified_cnt, total_cnt) == (1, 2)
    assert get_verified_remediation_counts([]) == (0, 0)

    mapping = map_remediations_by_finding(res.remediations)
    assert "SEC-001" in mapping
    assert "CODE-001" in mapping
    assert mapping["SEC-001"].verified is True


# ── Unit Tests: Visual Builders & HTML Safety ────────────────────────────────

def test_svg_gauges_table_and_code_viewer_escaping():
    """Ensures SVGs, PR prioritized table, and code viewer render cleanly with XSS escaping."""
    gauge_svg = build_health_gauge_svg(85, "B")
    assert "<svg" in gauge_svg
    assert "85" in gauge_svg
    assert "GRADE B" in gauge_svg
    assert "#22C55E" in gauge_svg

    donut_empty = build_severity_donut_svg({"CRITICAL": 0, "HIGH": 0})
    assert "CLEAN" in donut_empty

    donut_active = build_severity_donut_svg({"CRITICAL": 2, "HIGH": 1})
    assert "ISSUES" in donut_active
    assert "3" in donut_active

    xss_code = "line1 = '<script>alert(1)</script>'\ncursor.execute(q)\n"
    xss_finding = _make_finding("SEC-999", title="XSS <img onerror>", line_start=1, line_end=1)
    viewer_html = build_code_viewer_html(xss_code, [xss_finding])
    assert "<script>alert(1)</script>" not in viewer_html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in viewer_html
    assert "rgba(239, 68, 68, 0.16)" in viewer_html
    assert "SEC-999" in viewer_html

    assert "VERIFIED FIX" in verified_badge_html(True)
    assert "MANUAL REVIEW" in verified_badge_html(False)
    assert "Grounded in Knowledge Base" in grounding_badge_html(True)
    assert "Not covered by Knowledge Base" in grounding_badge_html(False)
    assert "badge-HIGH" in badge_html("high")

    pr_table = build_prioritized_fixes_table_html(
        [{"finding_id": "SEC-001", "title": "SQLi <bad>", "severity": "CRITICAL", "effort": "Medium", "reason": "Fix fast"}]
    )
    assert "<table class='report-table'>" in pr_table
    assert "&lt;bad&gt;" in pr_table
    assert "Fix fast" in pr_table


# ── Unit Tests: JSON / Markdown Export & Input Validation / Samples ──────────

def test_json_and_markdown_export():
    """Checks JSON serialization and PR markdown export (direct + fallback)."""
    res = _make_sample_analysis_result()

    json_str = export_results_json(res)
    parsed = json.loads(json_str)
    assert parsed["filename"] == "sample.py"
    assert len(parsed["findings"]) == 3
    assert parsed["health_score"]["score"] == 72

    md_str = export_pr_markdown(res)
    assert "# Pull Request Security & Quality Review" in md_str

    # Fallback when pr_summary is None
    res_no_pr = res.model_copy(update={"pr_summary": None})
    fallback_md = export_pr_markdown(res_no_pr)
    assert "SQL Injection" in fallback_md
    assert "Total Findings:** 3" in fallback_md


def test_validate_submission_input_and_sample_loader():
    """Validates input guards (empty, unsupported language, size, line limit) and samples."""
    ok_empty, err_empty = validate_submission_input("   ", "python")
    assert ok_empty is False and err_empty is not None

    ok_lang, err_lang = validate_submission_input("print(1)", "ruby")
    assert ok_lang is False and "Unsupported language" in (err_lang or "")

    ok_size, err_size = validate_submission_input("x = 1\n", "python", max_bytes=3)
    assert ok_size is False and "exceeds" in (err_size or "")

    ok_lines, err_lines = validate_submission_input("a=1\nb=2\nc=3\n", "python", max_lines=2)
    assert ok_lines is False and "exceeding" in (err_lines or "")

    ok_valid, err_valid = validate_submission_input("def f():\n    return 1\n", "python")
    assert ok_valid is True and err_valid is None

    py_code, py_name = load_sample_code("python")
    java_code, java_name = load_sample_code("java")
    assert py_name == "planted_security.py" and "sqlite3" in py_code
    assert java_name == "PlantedSecurity.java" and "PlantedSecurity" in java_code


# ── Smoke Test: Streamlit AppTest ────────────────────────────────────────────

def test_streamlit_app_smoke_via_apptest():
    """
    Smoke test using streamlit.testing.v1.AppTest:
    - Loads app/app.py cleanly without exceptions
    - Handles chat assistant before code analysis cleanly
    - Loads the vulnerable Python sample, runs analysis, verifies tabs & cached result
    - Sends a follow-up question to ChatAssistant via chat_input without exceptions
    """
    try:
        from streamlit.testing.v1 import AppTest
    except Exception as exc:
        pytest.skip(f"streamlit.testing.v1.AppTest unavailable: {exc}")

    if not _asyncio_loopback_available():
        pytest.skip("Asyncio loopback socket creation blocked in current sandbox environment.")

    app_path = str(Path(__file__).resolve().parent.parent / "app" / "app.py")
    at = AppTest.from_file(app_path, default_timeout=90)
    at.run()
    assert not at.exception, f"Initial render raised exception: {at.exception}"
    assert len(at.tabs) == 4

    # 1. Empty submission shows friendly warning, never crashes
    analyze_btn_empty = next(b for b in at.button if "Analyze code" in b.label)
    analyze_btn_empty.click().run()
    assert not at.exception, f"Empty submit raised exception: {at.exception}"
    assert len(at.warning) >= 1

    # 2. Chat before analysis should work gracefully with zero exceptions
    assert len(at.chat_input) >= 1
    at.chat_input[0].set_value("What is SQL injection?").run()
    assert not at.exception, f"Pre-analysis chat raised exception: {at.exception}"
    assert len(at.session_state["chat_history"]) >= 2

    # 3. Click "Load vulnerable Python sample" button & analyze
    py_btn = next(b for b in at.button if "Load vulnerable Python sample" in b.label)
    py_btn.click().run()
    assert not at.exception, f"Python sample load raised exception: {at.exception}"
    assert "sqlite3" in at.session_state["paste_area"]

    analyze_btn = next(b for b in at.button if "Analyze code" in b.label)
    analyze_btn.click().run()
    assert not at.exception, f"Python pipeline analysis raised exception: {at.exception}"
    assert "analysis_result" in at.session_state
    assert len(at.session_state["analysis_result"]["findings"]) > 0
    assert at.session_state["analysis_result"]["filename"] == "planted_security.py"

    # 4. Ask a post-analysis question about line 18 & verify finding filter doesn't fail
    at.chat_input[0].set_value("Why is line 18 flagged?").run()
    assert not at.exception, f"Post-analysis chat raised exception: {at.exception}"
    history = at.session_state["chat_history"]
    assert len(history) >= 2
    assert any("SEC-" in msg.get("content", "") or "SQL" in msg.get("content", "") for msg in history)

    search_boxes = [ti for ti in at.text_input if "Title, CWE" in (ti.placeholder or "")]
    if search_boxes:
        search_boxes[0].set_value("SQL").run()
        assert not at.exception, f"Filter search raised exception: {at.exception}"

    # 5. Clear chat button resets conversation cleanly, then test starter & follow-up buttons
    clear_btn = next(b for b in at.button if "Clear chat" in b.label)
    clear_btn.click().run()
    assert not at.exception, f"Clear chat raised exception: {at.exception}"
    assert at.session_state["chat_history"] == []

    starter_btn = next(b for b in at.button if b.label == "What should I fix first?")
    starter_btn.click().run()
    assert not at.exception, f"Starter button raised exception: {at.exception}"
    assert len(at.session_state["chat_history"]) == 2

    followup_btn = next(
        b for b in at.button
        if b.key and b.key.startswith("followup_")
    )
    followup_btn.click().run()
    assert not at.exception, f"Follow-up button raised exception: {at.exception}"
    assert len(at.session_state["chat_history"]) == 4

    # 6. Click "Load vulnerable Java sample" button & analyze
    java_btn = next(b for b in at.button if "Load vulnerable Java sample" in b.label)
    java_btn.click().run()
    assert not at.exception, f"Java sample load raised exception: {at.exception}"
    assert "PlantedSecurity" in at.session_state["paste_area"]

    analyze_btn_java = next(b for b in at.button if "Analyze code" in b.label)
    analyze_btn_java.click().run()
    assert not at.exception, f"Java pipeline analysis raised exception: {at.exception}"
    assert at.session_state["analysis_result"]["filename"] == "PlantedSecurity.java"
    assert len(at.session_state["analysis_result"]["findings"]) > 0
