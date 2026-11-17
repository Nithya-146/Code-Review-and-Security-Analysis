"""
Fast Regression Tests for End-to-End Evaluation Quality Thresholds (Milestone 4, Step 2).

Guards against regressions in:
  1. Detection recall, precision, F1 (overall, security, code quality) and clean-file FP rate
  2. Severity classification accuracy and multi-run severity/score consistency
  3. Remediation syntax validity, specificity, and two-tier self-verification
  4. RAG retrieval Hit Rate@3, Precision@3, grounded citation rate, and out-of-scope guards
  5. Persistence and threshold compliance of generated evaluation artifacts
"""

import ast
import json
from pathlib import Path

import javalang

from agents.chat_assistant import ChatAssistant
from agents.orchestrator import analyze
from agents.remediation_agent import RemediationAgent
from kb.retriever import retriever_singleton
from tests.eval.run_eval import (
    EXPECTED_DIR,
    RAG_IN_SCOPE_QUESTIONS,
    RAG_OUT_OF_SCOPE_QUESTIONS,
    RESULTS_DIR,
    SAMPLES_DIR,
    _finding_category_group,
    compute_prf,
    match_sample_findings,
)


def test_regression_detection_recall_precision_and_clean_fp():
    """Fails if overall/security/quality recall or precision drops below 0.95 or clean sample has FPs."""
    expected_files = sorted(EXPECTED_DIR.glob("*.json"))
    assert len(expected_files) >= 7

    ov_tp = ov_fp = ov_fn = 0
    sec_tp = sec_fp = sec_fn = 0
    qual_tp = qual_fp = qual_fn = 0

    for exp_path in expected_files:
        spec = json.loads(exp_path.read_text(encoding="utf-8"))
        sample_file = spec["sample_file"]
        language = spec["language"]
        expected_issues = spec["expected_issues"]
        code = (SAMPLES_DIR / sample_file).read_text(encoding="utf-8")

        # Skip remediation & PR summary here to keep regression check fast (<2s total)
        res = analyze(
            code,
            language=language,
            filename=sample_file,
            generate_remediations=False,
            generate_pr_summary=False,
        )

        if spec.get("complexity") == "clean":
            assert len(res.findings) == 0, f"Clean sample {sample_file} produced false positives: {res.findings}"

        m_all = match_sample_findings(res.findings, expected_issues)
        ov_tp += m_all["tp"]
        ov_fp += m_all["fp"]
        ov_fn += m_all["fn"]

        m_sec = match_sample_findings(
            [f for f in res.findings if _finding_category_group(f) == "security"],
            [e for e in expected_issues if e["category"] == "security"],
        )
        sec_tp += m_sec["tp"]
        sec_fp += m_sec["fp"]
        sec_fn += m_sec["fn"]

        m_qual = match_sample_findings(
            [f for f in res.findings if _finding_category_group(f) == "code_quality"],
            [e for e in expected_issues if e["category"] == "code_quality"],
        )
        qual_tp += m_qual["tp"]
        qual_fp += m_qual["fp"]
        qual_fn += m_qual["fn"]

    overall = compute_prf(ov_tp, ov_fp, ov_fn)
    security = compute_prf(sec_tp, sec_fp, sec_fn)
    quality = compute_prf(qual_tp, qual_fp, qual_fn)

    assert overall["recall"] >= 0.95, f"Overall recall regressed: {overall}"
    assert overall["precision"] >= 0.95, f"Overall precision regressed: {overall}"
    assert overall["f1"] >= 0.95, f"Overall F1 regressed: {overall}"
    assert security["recall"] >= 0.95, f"Security recall regressed: {security}"
    assert quality["precision"] >= 0.95, f"Code quality precision regressed: {quality}"


def test_regression_severity_accuracy_and_consistency():
    """Fails if severity classification drops below 95% or 3-run consistency drops below 100%."""
    for sample_name, lang in [("py_complex.py", "python"), ("JavaComplex.java", "java")]:
        spec = json.loads((EXPECTED_DIR / f"{Path(sample_name).stem}.json").read_text(encoding="utf-8"))
        code = (SAMPLES_DIR / sample_name).read_text(encoding="utf-8")

        runs = [
            analyze(code, language=lang, filename=sample_name, generate_remediations=False, generate_pr_summary=False)
            for _ in range(3)
        ]

        # Severity accuracy against ground truth
        matched = match_sample_findings(runs[0].findings, spec["expected_issues"])["matched_pairs"]
        assert len(matched) > 0
        exact = sum(
            1 for f, e in matched
            if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == e["expected_severity"]
        )
        assert (exact / len(matched)) >= 0.95

        # 3-run determinism for both severity label and numeric severity_score
        signatures = [
            sorted((f.title, f.line_start, f.severity.value, round(float(f.severity_score), 3)) for f in r.findings)
            for r in runs
        ]
        assert signatures[0] == signatures[1] == signatures[2], f"Non-deterministic severities on {sample_name}"


def test_regression_remediation_syntax_and_verification():
    """Fails if line-level Python/Java fixes produce syntax errors or fail two-tier verification."""
    rem_agent = RemediationAgent()
    for sample_name, lang in [("py_small.py", "python"), ("JavaSmall.java", "java")]:
        code = (SAMPLES_DIR / sample_name).read_text(encoding="utf-8")
        res = analyze(code, language=lang, filename=sample_name, generate_pr_summary=False)
        assert len(res.findings) == 3
        assert len(res.remediations) == 3

        verified_count = 0
        rem_map = {r.finding_id: r for r in res.remediations}
        for f in res.findings:
            rem = rem_map[f.id]
            assert rem.corrected_code.strip() != rem.original_code.strip()
            assert not rem.corrected_code.strip().startswith(("# Remediated:", "// Remediated:"))
            if rem.verified:
                verified_count += 1
            candidate = rem_agent._build_candidate_code(code, f.line_start, f.line_end, rem.corrected_code, lang)
            if lang == "python":
                ast.parse(candidate)
            else:
                javalang.parse.parse(candidate)

        assert verified_count == 3, f"Expected all 3 fixes verified in {sample_name}, got {verified_count}"


def test_regression_rag_hit_rate_grounding_and_oos():
    """Fails if RAG Hit@3 drops below 0.95, P@3 below 0.75, citation rate below 0.95, or OOS fails."""
    retriever = retriever_singleton()
    py_complex_code = (SAMPLES_DIR / "py_complex.py").read_text(encoding="utf-8")
    complex_res = analyze(
        py_complex_code,
        language="python",
        filename="py_complex.py",
        generate_remediations=False,
        generate_pr_summary=False,
    )
    assistant = ChatAssistant(
        analysis_result=complex_res,
        code=py_complex_code,
        language="python",
        retriever=retriever,
    )

    hits_at_3 = 0
    cited = 0
    total_slots = 0
    relevant_slots = 0

    for item in RAG_IN_SCOPE_QUESTIONS:
        q = item["question"]
        exp_sources = set(item["expected_sources"])
        retr_q = (
            f"{complex_res.findings[0].title} {complex_res.findings[0].cwe_id or ''} {q}"
            if item.get("is_followup") and complex_res.findings
            else q
        )
        raw = retriever.search(retr_q, k=3)
        sources = [h["source"] for h in raw]
        if any(s in exp_sources for s in sources):
            hits_at_3 += 1
        total_slots += len(sources)
        relevant_slots += sum(1 for s in sources if s in exp_sources)

        resp = assistant.ask(q)
        if resp.grounded and len(resp.citations) > 0:
            cited += 1

    n = len(RAG_IN_SCOPE_QUESTIONS)
    assert (hits_at_3 / n) >= 0.95, f"RAG Hit@3 regressed: {hits_at_3}/{n}"
    assert (relevant_slots / total_slots) >= 0.75, f"RAG Precision@3 regressed: {relevant_slots}/{total_slots}"
    assert (cited / n) >= 0.95, f"Assistant grounded citation rate regressed: {cited}/{n}"

    # All 3 out-of-scope questions must be ungrounded and declined cleanly
    for item in RAG_OUT_OF_SCOPE_QUESTIONS:
        resp = assistant.ask(item["question"])
        assert resp.grounded is False, f"OOS question wrongly grounded: {item['question']}"
        assert resp.intent == "out_of_scope"
        assert len(resp.citations) == 0


def test_regression_eval_artifacts_present_and_passing():
    """Verifies generated Milestone 4 evaluation artifacts exist and meet recorded quality gates."""
    json_path = RESULTS_DIR / "eval_results.json"
    report_path = RESULTS_DIR / "eval_report.md"
    opt_log_path = RESULTS_DIR / "optimization_log.md"

    assert json_path.exists()
    assert report_path.exists()
    assert opt_log_path.exists()

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["detection_accuracy"]["overall"]["recall"] >= 0.95
    assert data["detection_accuracy"]["overall"]["precision"] >= 0.95
    assert data["severity_consistency"]["same_severity_rate"] == 1.0
    assert data["rag_relevance"]["hit_rate_at_3"] >= 0.95
    assert data["rag_relevance"]["citation_rate"] >= 0.95
    assert data["report_completeness"]["pass_rate"] == 1.0

