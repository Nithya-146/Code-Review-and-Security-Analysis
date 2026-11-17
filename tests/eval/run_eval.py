"""
Comprehensive End-to-End Evaluation Harness (Milestone 4, Step 2).

Evaluates the AI Code Review & Security Analysis Agent across all 6 dimensions:
  1. Detection Accuracy (Precision, Recall, F1 — per sample, overall, security vs quality)
  2. Severity Classification Accuracy + 5x5 Confusion Matrix
  3. Severity Consistency across 3 repeated runs per sample
  4. Remediation Quality (specificity, syntax validity via ast/javalang, vulnerable pattern removal)
  5. RAG Retrieval Relevance (20 in-scope questions Hit Rate@3 & citation rate + 3 out-of-scope guards)
  6. PDF Report Completeness (all 7 sections, matching finding counts, non-empty sections, chart image)

Outputs structured JSON to tests/eval/results/eval_results.json and a human-readable
report to tests/eval/results/eval_report.md.
"""

from __future__ import annotations

import ast
import io
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import javalang
from pypdf import PdfReader

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.chat_assistant import ChatAssistant
from agents.orchestrator import analyze
from agents.remediation_agent import RemediationAgent
from app.report_generator import generate_report
from app.schemas import AnalysisResult, Finding, RemediationResult
from kb.retriever import retriever_singleton

SAMPLES_DIR = PROJECT_ROOT / "tests" / "samples"
EXPECTED_DIR = SAMPLES_DIR / "expected"
RESULTS_DIR = PROJECT_ROOT / "tests" / "eval" / "results"

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Canonical synonyms mapping expected issue `type` -> detector CWEs or title keywords
TYPE_MATCH_RULES: Dict[str, Dict[str, List[str]]] = {
    "sql_injection": {"cwes": ["CWE-89"], "keywords": ["sql injection", "sqli"]},
    "command_injection": {"cwes": ["CWE-78"], "keywords": ["command injection"]},
    "xss": {"cwes": ["CWE-79"], "keywords": ["cross-site scripting", "xss"]},
    "hardcoded_secret": {"cwes": ["CWE-798"], "keywords": ["hardcoded secret", "hardcoded credential"]},
    "weak_crypto": {"cwes": ["CWE-327", "CWE-328"], "keywords": ["weak crypto", "weak hash", "md5", "sha1"]},
    "insecure_deserialization": {"cwes": ["CWE-502"], "keywords": ["deserialization", "pickle", "objectinputstream"]},
    "path_traversal": {"cwes": ["CWE-22"], "keywords": ["path traversal"]},
    "insecure_tls": {"cwes": ["CWE-295"], "keywords": ["insecure tls", "ssrf and insecure tls", "certificate"]},
    "csrf": {"cwes": ["CWE-352"], "keywords": ["csrf"]},
    "insecure_auth": {"cwes": ["CWE-287", "CWE-306"], "keywords": ["insecure authentication", "plaintext password", "weak auth"]},
    "broken_access_control": {"cwes": ["CWE-862", "CWE-284", "CWE-639"], "keywords": ["broken access control", "missing auth", "missing authorization", "unprotected admin"]},
    "god_class": {"cwes": [], "keywords": ["god class"]},
    "long_method": {"cwes": [], "keywords": ["long function", "long method"]},
    "deep_nesting": {"cwes": [], "keywords": ["deep nesting", "deeply nested", "deep control flow nesting", "nesting"]},
    "duplicate_code": {"cwes": [], "keywords": ["duplicate code"]},
    "too_many_parameters": {"cwes": [], "keywords": ["too many parameters"]},
    "magic_number": {"cwes": [], "keywords": ["magic number"]},
    "broad_exception": {"cwes": [], "keywords": ["broad exception", "bare except", "overly broad", "generic exception", "broad catch"]},
    "cyclomatic_complexity": {"cwes": [], "keywords": ["cyclomatic complexity"]},
}

# 20 in-scope RAG evaluation questions + expected KB source documents
RAG_IN_SCOPE_QUESTIONS: List[Dict[str, Any]] = [
    {
        "id": "Q01",
        "question": "How do I prevent SQL injection in Python using parameterized queries?",
        "expected_sources": ["A05_injection.md", "owasp_sqli_cheatsheet.txt"],
        "topic": "SQL Injection",
    },
    {
        "id": "Q02",
        "question": "What are the best practices for storing API keys and secrets securely?",
        "expected_sources": ["owasp_secrets_cheatsheet.txt", "A07_authentication_failures.md", "A02_security_misconfiguration.md"],
        "topic": "Secrets Management",
    },
    {
        "id": "Q03",
        "question": "What is Broken Access Control and how can I prevent IDOR vulnerabilities?",
        "expected_sources": ["A01_broken_access_control.md"],
        "topic": "Broken Access Control",
    },
    {
        "id": "Q04",
        "question": "Why is Cross-Site Scripting (XSS) dangerous and how should output be escaped?",
        "expected_sources": ["A05_injection.md"],
        "topic": "XSS",
    },
    {
        "id": "Q05",
        "question": "What is CSRF and how do anti-CSRF tokens protect web applications?",
        "expected_sources": ["A01_broken_access_control.md", "A02_security_misconfiguration.md", "A06_insecure_design.md"],
        "topic": "CSRF",
    },
    {
        "id": "Q06",
        "question": "Why are MD5 and SHA-1 considered weak cryptographic hash functions?",
        "expected_sources": ["A04_cryptographic_failures.md"],
        "topic": "Cryptographic Failures",
    },
    {
        "id": "Q07",
        "question": "What are the risks of insecure deserialization using Python pickle or Java ObjectInputStream?",
        "expected_sources": ["A08_software_or_data_integrity_failures.md"],
        "topic": "Insecure Deserialization",
    },
    {
        "id": "Q08",
        "question": "How do I fix command injection when calling system commands?",
        "expected_sources": ["A05_injection.md"],
        "topic": "Command Injection",
    },
    {
        "id": "Q09",
        "question": "How do I prevent path traversal attacks when opening user-supplied filenames?",
        "expected_sources": ["A01_broken_access_control.md"],
        "topic": "Path Traversal",
    },
    {
        "id": "Q10",
        "question": "What security misconfigurations like debug mode or permissive CORS should be avoided?",
        "expected_sources": ["A02_security_misconfiguration.md"],
        "topic": "Security Misconfiguration",
    },
    {
        "id": "Q11",
        "question": "How can I mitigate software supply chain and vulnerable dependency risks?",
        "expected_sources": ["A03_software_supply_chain_failures.md"],
        "topic": "Supply Chain Failures",
    },
    {
        "id": "Q12",
        "question": "What is insecure design and how does threat modeling help prevent it?",
        "expected_sources": ["A06_insecure_design.md"],
        "topic": "Insecure Design",
    },
    {
        "id": "Q13",
        "question": "What causes authentication failures and how should passwords and sessions be handled?",
        "expected_sources": ["A07_authentication_failures.md"],
        "topic": "Authentication Failures",
    },
    {
        "id": "Q14",
        "question": "What are security logging and alerting best practices to detect breaches?",
        "expected_sources": ["A09_security_logging_and_alerting_failures.md"],
        "topic": "Security Logging",
    },
    {
        "id": "Q15",
        "question": "Why is mishandling exceptions or catching bare Exception dangerous?",
        "expected_sources": ["A10_mishandling_of_exceptional_conditions.md", "code_smells_and_clean_code.md"],
        "topic": "Exception Handling",
    },
    {
        "id": "Q16",
        "question": "How should I refactor a God Class and reduce cyclomatic complexity?",
        "expected_sources": ["code_smells_and_clean_code.md"],
        "topic": "Clean Code / God Class",
    },
    {
        "id": "Q17",
        "question": "Why are magic numbers and deep nesting considered code smells?",
        "expected_sources": ["code_smells_and_clean_code.md"],
        "topic": "Code Smells",
    },
    {
        "id": "Q18",
        "question": "How do Java PreparedStatements defend against SQL injection?",
        "expected_sources": ["owasp_sqli_cheatsheet.txt", "A05_injection.md"],
        "topic": "Java PreparedStatement",
    },
    {
        "id": "Q19",
        "question": "How should secret rotation and vault storage be implemented for credentials?",
        "expected_sources": ["owasp_secrets_cheatsheet.txt"],
        "topic": "Secret Rotation",
    },
    {
        "id": "Q20",
        "question": "How do I fix finding 1?",
        "expected_sources": ["A05_injection.md", "owasp_sqli_cheatsheet.txt", "A08_software_or_data_integrity_failures.md"],
        "topic": "Remediation Follow-Up",
        "is_followup": True,
    },
]

RAG_OUT_OF_SCOPE_QUESTIONS: List[Dict[str, str]] = [
    {"id": "OOS01", "question": "What is the weather forecast in Tokyo tomorrow?"},
    {"id": "OOS02", "question": "How do I train a golden retriever puppy to sit?"},
    {"id": "OOS03", "question": "What is the average distance from Earth to Mars in kilometers?"},
]


# ── Helper Functions ─────────────────────────────────────────────────────────

def _finding_category_group(finding: Finding) -> str:
    """Maps a Finding to 'security' or 'code_quality'."""
    if finding.agent == "security_analysis":
        return "security"
    return "code_quality"


def _finding_matches_expected_type(finding: Finding, expected: Dict[str, Any]) -> bool:
    """Checks whether a Finding matches the expected issue's type and CWE."""
    exp_type = str(expected.get("type", "")).strip().lower()
    exp_cwe = str(expected.get("cwe") or "").strip().upper()
    rule = TYPE_MATCH_RULES.get(exp_type, {"cwes": [], "keywords": [exp_type.replace("_", " ")]})

    f_cwe = (finding.cwe_id or "").strip().upper()
    f_title = finding.title.strip().lower()

    if exp_cwe and f_cwe == exp_cwe:
        return True
    if f_cwe and f_cwe in rule["cwes"]:
        return True
    if any(kw in f_title for kw in rule["keywords"]):
        return True
    return False


def _line_matches_range(finding: Finding, line_range: Sequence[int], tolerance: int = 3) -> bool:
    """Checks if finding's line span overlaps expected [start, end] within +/- tolerance."""
    exp_start = int(line_range[0]) - tolerance
    exp_end = int(line_range[1]) + tolerance
    return not (finding.line_end < exp_start or finding.line_start > exp_end)


def match_sample_findings(
    detected: List[Finding],
    expected_issues: List[Dict[str, Any]],
    tolerance: int = 3,
) -> Dict[str, Any]:
    """Matches detected findings against expected_issues for one sample."""
    matched_exp: Set[int] = set()
    matched_det: Set[int] = set()
    matched_pairs: List[Tuple[Finding, Dict[str, Any]]] = []

    for f_idx, f in enumerate(detected):
        f_group = _finding_category_group(f)
        for e_idx, exp in enumerate(expected_issues):
            if e_idx in matched_exp:
                continue
            if f_group != exp["category"]:
                continue
            if not _finding_matches_expected_type(f, exp):
                continue
            if _line_matches_range(f, exp["line_range"], tolerance=tolerance):
                matched_exp.add(e_idx)
                matched_det.add(f_idx)
                matched_pairs.append((f, exp))
                break

    false_positives = [f for i, f in enumerate(detected) if i not in matched_det]
    false_negatives = [e for i, e in enumerate(expected_issues) if i not in matched_exp]

    return {
        "tp": len(matched_pairs),
        "fp": len(false_positives),
        "fn": len(false_negatives),
        "matched_pairs": matched_pairs,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }


def compute_prf(tp: int, fp: int, fn: int) -> Dict[str, float]:
    """Computes precision, recall, and F1 score cleanly."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fn == 0 else 0.0)
    recall = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if fp == 0 else 0.0)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def _check_remediation_quality_item(
    finding: Finding,
    rem: Optional[RemediationResult],
    source_code: str,
    language: str,
    rem_agent: RemediationAgent,
) -> Dict[str, Any]:
    """
    Evaluates a single finding's remediation on 4 strict criteria:
    1. Specific (not a generic '# Remediated:' / '// Remediated:' fallback comment)
    2. Contains non-empty corrected_code different from original_code
    3. Corrected candidate code syntax-parses cleanly (ast.parse / javalang.parse.parse)
    4. Vulnerable pattern no longer present in corrected_code (verified or pattern-free)
    """
    if rem is None:
        return {
            "finding_id": finding.id,
            "title": finding.title,
            "cwe": finding.cwe_id,
            "language": language,
            "has_remediation": False,
            "specific": False,
            "has_corrected_code": False,
            "syntax_valid": False,
            "pattern_removed": False,
            "verified": False,
        }

    corrected = (rem.corrected_code or "").strip()
    original = (rem.original_code or "").strip()

    is_generic_fallback = (
        corrected.startswith("# Remediated:")
        or corrected.startswith("// Remediated:")
        or "Automated fix template not available" in (rem.verification_note or "")
    )
    has_corrected = bool(corrected) and corrected != original
    specific = has_corrected and not is_generic_fallback

    # Syntax check by substituting corrected code into source or parsing snippet
    syntax_valid = False
    if has_corrected:
        candidate = rem_agent._build_candidate_code(
            original_code=source_code,
            start_line=finding.line_start,
            end_line=finding.line_end,
            replacement_snippet=rem.corrected_code,
            language=language,
        )
        if language == "python":
            try:
                ast.parse(candidate)
                syntax_valid = True
            except SyntaxError:
                # Fallback: check standalone snippet syntax
                try:
                    ast.parse(corrected)
                    syntax_valid = True
                except SyntaxError:
                    syntax_valid = False
        else:
            try:
                javalang.parse.parse(candidate)
                syntax_valid = True
            except Exception:
                # Try wrapping statement inside dummy class/method
                try:
                    javalang.parse.parse(f"class _Check {{ void _m() throws Exception {{ {corrected} }} }}")
                    syntax_valid = True
                except Exception:
                    syntax_valid = False

    # Pattern removal check
    pattern_removed = False
    if specific and syntax_valid:
        if rem.verified:
            pattern_removed = True
        else:
            # Verify raw dangerous markers are gone from corrected_code
            c_low = corrected.lower()
            bad_markers = [
                "os.system(",
                "runtime.getruntime().exec",
                "pickle.loads",
                "objectinputstream",
                "hashlib.md5",
                '"md5"',
                "verify=false",
                "wtf_csrf_enabled = false",
                "csrf().disable()",
                "except exception:",
                "catch (exception",
            ]
            pattern_removed = not any(m in c_low for m in bad_markers)

    return {
        "finding_id": finding.id,
        "title": finding.title,
        "cwe": finding.cwe_id,
        "language": language,
        "has_remediation": True,
        "specific": specific,
        "has_corrected_code": has_corrected,
        "syntax_valid": syntax_valid,
        "pattern_removed": pattern_removed,
        "verified": bool(rem.verified),
    }


def _evaluate_pdf_completeness(
    result: AnalysisResult,
    source_code: str,
    filename: str,
    language: str,
) -> Dict[str, Any]:
    """Generates PDF report and validates all 7 sections, finding counts, and chart."""
    pdf_bytes = generate_report(result, source_code, filename, language)
    valid_header = pdf_bytes.startswith(b"%PDF")
    reader = PdfReader(io.BytesIO(pdf_bytes))
    full_text = "\n".join((p.extract_text() or "") for p in reader.pages)

    required_sections = [
        ("Cover Page", "AI Code Review & Security Analysis Report"),
        ("1. Executive Overview", "1. Executive Overview"),
        ("2. Severity Breakdown", "2. Severity Breakdown"),
        ("3. Findings Summary Table", "3. Findings Summary Table"),
        ("4. Detailed Findings", "4. Detailed Findings"),
        ("5. Prioritized Remediation Roadmap", "5. Prioritized Remediation Roadmap"),
        ("6. Overall Code Quality Assessment", "6. Overall Code Quality Assessment"),
    ]

    missing_sections: List[str] = []
    empty_sections: List[str] = []
    positions: List[Tuple[str, int]] = []

    for label, marker in required_sections:
        pos = full_text.find(marker)
        if pos == -1:
            missing_sections.append(label)
        else:
            positions.append((label, pos + len(marker)))

    # Check non-empty body between consecutive section headings
    positions.sort(key=lambda x: x[1])
    for idx, (label, start_pos) in enumerate(positions):
        end_pos = positions[idx + 1][1] - len(required_sections[idx + 1][1]) if idx + 1 < len(positions) else len(full_text)
        section_body = full_text[start_pos:max(start_pos, end_pos)].strip()
        if len(section_body) < 15:
            empty_sections.append(label)

    # Check finding count matches pipeline result
    expected_count = len(result.findings)
    count_pattern = re.search(r"Total Findings\s+(\d+)", full_text)
    count_matches = (count_pattern is not None and int(count_pattern.group(1)) == expected_count)

    # Check chart image embedded
    image_count = sum(len(p.images) for p in reader.pages)

    return {
        "filename": filename,
        "valid_header": valid_header,
        "page_count": len(reader.pages),
        "all_7_sections_present": len(missing_sections) == 0,
        "missing_sections": missing_sections,
        "no_empty_sections": len(empty_sections) == 0,
        "empty_sections": empty_sections,
        "finding_count_matches": count_matches,
        "expected_finding_count": expected_count,
        "embedded_images": image_count,
        "passed": (
            valid_header
            and len(missing_sections) == 0
            and len(empty_sections) == 0
            and count_matches
            and image_count >= 1
        ),
    }


def _evaluate_rag(
    complex_result: AnalysisResult,
    complex_code: str,
) -> Dict[str, Any]:
    """Evaluates RAG retrieval Hit Rate@3, citation rate, and 3 out-of-scope guards."""
    retriever = retriever_singleton()
    assistant = ChatAssistant(
        analysis_result=complex_result,
        code=complex_code,
        language="python",
        retriever=retriever,
    )

    in_scope_details: List[Dict[str, Any]] = []
    hit_at_1_count = 0
    hit_at_3_count = 0
    cited_count = 0
    expected_cited_count = 0
    total_top3_slots = 0
    relevant_top3_slots = 0

    for item in RAG_IN_SCOPE_QUESTIONS:
        q = item["question"]
        exp_sources = set(item["expected_sources"])
        is_followup = bool(item.get("is_followup", False))

        # 1. Direct Retriever Hit@1 / Hit@3 / Precision@3
        if is_followup and complex_result.findings:
            f0 = complex_result.findings[0]
            retr_q = f"{f0.title} {f0.cwe_id or ''} {f0.explanation} {q}"
        else:
            retr_q = q

        raw_hits = retriever.search(retr_q, k=3)
        top3_sources = [h.get("source", "") for h in raw_hits]
        hit_at_1 = bool(top3_sources) and (top3_sources[0] in exp_sources)
        hit_at_3 = any(src in exp_sources for src in top3_sources)
        if hit_at_1:
            hit_at_1_count += 1
        if hit_at_3:
            hit_at_3_count += 1
        total_top3_slots += len(top3_sources)
        relevant_top3_slots += sum(1 for src in top3_sources if src in exp_sources)

        # 2. Full ChatAssistant response
        resp = assistant.ask(q)
        resp_sources = [c.source for c in resp.citations]
        has_citation = bool(resp.grounded and len(resp.citations) > 0)
        if has_citation:
            cited_count += 1
        if any(src in exp_sources for src in resp_sources):
            expected_cited_count += 1

        in_scope_details.append(
            {
                "id": item["id"],
                "topic": item["topic"],
                "question": q,
                "expected_sources": item["expected_sources"],
                "top3_sources": top3_sources,
                "top3_scores": [h.get("similarity_score", 0.0) for h in raw_hits],
                "hit_at_3": hit_at_3,
                "assistant_intent": resp.intent,
                "assistant_grounded": resp.grounded,
                "assistant_citations": resp_sources,
                "has_citation": has_citation,
            }
        )

    oos_details: List[Dict[str, Any]] = []
    oos_declined_count = 0
    for item in RAG_OUT_OF_SCOPE_QUESTIONS:
        q = item["question"]
        resp = assistant.ask(q)
        declined = (
            (not resp.grounded)
            and len(resp.citations) == 0
            and (
                resp.intent == "out_of_scope"
                or "outside" in resp.answer.lower()
                or "could not find" in resp.answer.lower()
                or "not covered" in resp.answer.lower()
            )
        )
        if declined:
            oos_declined_count += 1
        oos_details.append(
            {
                "id": item["id"],
                "question": q,
                "intent": resp.intent,
                "grounded": resp.grounded,
                "citations_count": len(resp.citations),
                "declined_properly": declined,
            }
        )

    n_in = len(RAG_IN_SCOPE_QUESTIONS)
    n_oos = len(RAG_OUT_OF_SCOPE_QUESTIONS)
    return {
        "total_in_scope": n_in,
        "hit_at_1_count": hit_at_1_count,
        "hit_rate_at_1": round(hit_at_1_count / n_in, 4) if n_in else 0.0,
        "hit_at_3_count": hit_at_3_count,
        "hit_rate_at_3": round(hit_at_3_count / n_in, 4) if n_in else 0.0,
        "precision_at_3": round(relevant_top3_slots / total_top3_slots, 4) if total_top3_slots else 0.0,
        "cited_count": cited_count,
        "citation_rate": round(cited_count / n_in, 4) if n_in else 0.0,
        "expected_source_citation_rate": round(expected_cited_count / n_in, 4) if n_in else 0.0,
        "total_out_of_scope": n_oos,
        "out_of_scope_declined": oos_declined_count,
        "out_of_scope_accuracy": round(oos_declined_count / n_oos, 4) if n_oos else 0.0,
        "in_scope_details": in_scope_details,
        "out_of_scope_details": oos_details,
    }


def run_full_evaluation(
    write_outputs: bool = True,
    samples_dir: Optional[Path] = None,
    expected_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Executes all 6 evaluation dimensions across all samples in samples_dir / expected_dir."""
    active_samples_dir = samples_dir or SAMPLES_DIR
    active_expected_dir = expected_dir or EXPECTED_DIR
    expected_files = sorted(active_expected_dir.glob("*.json"))
    if not expected_files:
        raise FileNotFoundError(f"No ground-truth expected JSON files found in {active_expected_dir}")

    rem_agent = RemediationAgent()
    per_sample_results: List[Dict[str, Any]] = []

    overall_tp = overall_fp = overall_fn = 0
    sec_tp = sec_fp = sec_fn = 0
    qual_tp = qual_fp = qual_fn = 0

    # Severity accuracy + confusion matrix: matrix[expected][predicted]
    confusion: Dict[str, Dict[str, int]] = {
        exp: {pred: 0 for pred in SEVERITY_LEVELS} for exp in SEVERITY_LEVELS
    }
    sev_exact_matches = 0
    sev_total_matched = 0

    # Consistency across 3 runs
    consistency_total_keys = 0
    consistency_same_sev = 0
    consistency_same_score = 0

    # Remediation quality
    rem_items: List[Dict[str, Any]] = []

    # PDF completeness
    pdf_checks: List[Dict[str, Any]] = []

    # Cache complex python result for RAG eval
    complex_py_result: Optional[AnalysisResult] = None
    complex_py_code: str = ""

    for exp_path in expected_files:
        spec = json.loads(exp_path.read_text(encoding="utf-8"))
        sample_file = spec["sample_file"]
        language = spec["language"]
        complexity = spec.get("complexity", "unknown")
        expected_issues = spec.get("expected_issues", [])

        code_path = active_samples_dir / sample_file
        source_code = code_path.read_text(encoding="utf-8")

        # Run 3 times for severity consistency
        runs: List[AnalysisResult] = [
            analyze(source_code, language=language, filename=sample_file)
            for _ in range(3)
        ]
        primary_res = runs[0]

        if sample_file == "py_complex.py":
            complex_py_result = primary_res
            complex_py_code = source_code

        # 1. Detection accuracy (overall + security vs quality)
        match_all = match_sample_findings(primary_res.findings, expected_issues)
        sec_det = [f for f in primary_res.findings if _finding_category_group(f) == "security"]
        sec_exp = [e for e in expected_issues if e["category"] == "security"]
        match_sec = match_sample_findings(sec_det, sec_exp)

        qual_det = [f for f in primary_res.findings if _finding_category_group(f) == "code_quality"]
        qual_exp = [e for e in expected_issues if e["category"] == "code_quality"]
        match_qual = match_sample_findings(qual_det, qual_exp)

        overall_tp += match_all["tp"]
        overall_fp += match_all["fp"]
        overall_fn += match_all["fn"]
        sec_tp += match_sec["tp"]
        sec_fp += match_sec["fp"]
        sec_fn += match_sec["fn"]
        qual_tp += match_qual["tp"]
        qual_fp += match_qual["fp"]
        qual_fn += match_qual["fn"]

        # 2. Severity classification accuracy + confusion matrix
        for finding, exp in match_all["matched_pairs"]:
            pred_sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            exp_sev = str(exp["expected_severity"]).upper()
            if exp_sev in confusion and pred_sev in confusion[exp_sev]:
                confusion[exp_sev][pred_sev] += 1
            sev_total_matched += 1
            if pred_sev == exp_sev:
                sev_exact_matches += 1

        # 3. Severity consistency across 3 runs
        run_maps: List[Dict[Tuple[str, int], Tuple[str, float]]] = []
        all_keys: Set[Tuple[str, int]] = set()
        for r in runs:
            rmap: Dict[Tuple[str, int], Tuple[str, float]] = {}
            for f in r.findings:
                key = (f.title, f.line_start)
                sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                rmap[key] = (sev_val, round(float(f.severity_score), 3))
                all_keys.add(key)
            run_maps.append(rmap)

        sample_same_sev = 0
        sample_same_score = 0
        for key in all_keys:
            sevs = [m[key][0] if key in m else None for m in run_maps]
            scores = [m[key][1] if key in m else None for m in run_maps]
            consistency_total_keys += 1
            if len(set(sevs)) == 1 and sevs[0] is not None:
                consistency_same_sev += 1
                sample_same_sev += 1
            if len(set(scores)) == 1 and scores[0] is not None:
                consistency_same_score += 1
                sample_same_score += 1

        # 4. Remediation quality
        rem_map = {r.finding_id: r for r in primary_res.remediations}
        for f in primary_res.findings:
            rem_items.append(
                _check_remediation_quality_item(
                    finding=f,
                    rem=rem_map.get(f.id),
                    source_code=source_code,
                    language=language,
                    rem_agent=rem_agent,
                )
            )

        # 6. PDF report completeness
        pdf_checks.append(_evaluate_pdf_completeness(primary_res, source_code, sample_file, language))

        per_sample_results.append(
            {
                "sample_file": sample_file,
                "language": language,
                "complexity": complexity,
                "expected_count": len(expected_issues),
                "detected_count": len(primary_res.findings),
                "overall": compute_prf(match_all["tp"], match_all["fp"], match_all["fn"]),
                "security": compute_prf(match_sec["tp"], match_sec["fp"], match_sec["fn"]),
                "code_quality": compute_prf(match_qual["tp"], match_qual["fp"], match_qual["fn"]),
                "consistency_keys": len(all_keys),
                "consistency_same_severity": sample_same_sev,
                "consistency_same_score": sample_same_score,
                "false_positives": [
                    {"title": f.title, "line": f.line_start, "agent": f.agent, "cwe": f.cwe_id}
                    for f in match_all["false_positives"]
                ],
                "false_negatives": [
                    {"type": e["type"], "line_range": e["line_range"], "category": e["category"], "cwe": e.get("cwe")}
                    for e in match_all["false_negatives"]
                ],
            }
        )

    # 5. RAG Retrieval Relevance
    if complex_py_result is None:
        complex_py_result = AnalysisResult(findings=[], language="python", filename="py_complex.py")
    rag_metrics = _evaluate_rag(complex_py_result, complex_py_code)

    # Aggregate Remediation metrics
    n_rem = len(rem_items)
    rem_summary = {
        "total_findings": n_rem,
        "specific_count": sum(1 for x in rem_items if x["specific"]),
        "specific_rate": round(sum(1 for x in rem_items if x["specific"]) / n_rem, 4) if n_rem else 1.0,
        "syntax_valid_count": sum(1 for x in rem_items if x["syntax_valid"]),
        "syntax_valid_rate": round(sum(1 for x in rem_items if x["syntax_valid"]) / n_rem, 4) if n_rem else 1.0,
        "pattern_removed_count": sum(1 for x in rem_items if x["pattern_removed"]),
        "pattern_removed_rate": round(sum(1 for x in rem_items if x["pattern_removed"]) / n_rem, 4) if n_rem else 1.0,
        "verified_count": sum(1 for x in rem_items if x["verified"]),
        "verified_rate": round(sum(1 for x in rem_items if x["verified"]) / n_rem, 4) if n_rem else 1.0,
        "failed_items": [x for x in rem_items if not (x["specific"] and x["syntax_valid"] and x["pattern_removed"])],
    }

    pdf_summary = {
        "total_reports": len(pdf_checks),
        "passed_reports": sum(1 for c in pdf_checks if c["passed"]),
        "pass_rate": round(sum(1 for c in pdf_checks if c["passed"]) / len(pdf_checks), 4) if pdf_checks else 1.0,
        "details": pdf_checks,
    }

    eval_data: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "samples_evaluated": len(per_sample_results),
        "detection_accuracy": {
            "overall": compute_prf(overall_tp, overall_fp, overall_fn),
            "security": compute_prf(sec_tp, sec_fp, sec_fn),
            "code_quality": compute_prf(qual_tp, qual_fp, qual_fn),
            "per_sample": per_sample_results,
        },
        "severity_classification": {
            "matched_findings": sev_total_matched,
            "exact_matches": sev_exact_matches,
            "accuracy": round(sev_exact_matches / sev_total_matched, 4) if sev_total_matched else 1.0,
            "confusion_matrix": confusion,
        },
        "severity_consistency": {
            "runs_per_sample": 3,
            "total_unique_findings": consistency_total_keys,
            "same_severity_count": consistency_same_sev,
            "same_severity_rate": round(consistency_same_sev / consistency_total_keys, 4) if consistency_total_keys else 1.0,
            "same_score_count": consistency_same_score,
            "same_score_rate": round(consistency_same_score / consistency_total_keys, 4) if consistency_total_keys else 1.0,
        },
        "remediation_quality": rem_summary,
        "rag_relevance": rag_metrics,
        "report_completeness": pdf_summary,
    }

    if write_outputs:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        (RESULTS_DIR / "eval_results.json").write_text(
            json.dumps(eval_data, indent=2), encoding="utf-8"
        )
        (RESULTS_DIR / "eval_report.md").write_text(
            format_eval_markdown(eval_data), encoding="utf-8"
        )

    return eval_data


def format_eval_markdown(data: Dict[str, Any]) -> str:
    """Formats evaluation results dictionary into a readable Markdown report."""
    det = data["detection_accuracy"]
    ov = det["overall"]
    sec = det["security"]
    qual = det["code_quality"]
    sev = data["severity_classification"]
    cons = data["severity_consistency"]
    rem = data["remediation_quality"]
    rag = data["rag_relevance"]
    pdf = data["report_completeness"]

    lines: List[str] = [
        "# End-to-End Evaluation Report (Milestone 4, Step 2)",
        "",
        f"- **Generated:** `{data['generated_at']}`",
        f"- **Samples Evaluated:** `{data['samples_evaluated']}` (3 Python, 3 Java, 1 Clean baseline)",
        "",
        "## 1. Detection Accuracy",
        "",
        "| Segment | TP | FP | FN | Precision | Recall | F1 |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
        f"| **Overall** | {ov['tp']} | {ov['fp']} | {ov['fn']} | {ov['precision']:.4f} | {ov['recall']:.4f} | **{ov['f1']:.4f}** |",
        f"| Security | {sec['tp']} | {sec['fp']} | {sec['fn']} | {sec['precision']:.4f} | {sec['recall']:.4f} | {sec['f1']:.4f} |",
        f"| Code Quality | {qual['tp']} | {qual['fp']} | {qual['fn']} | {qual['precision']:.4f} | {qual['recall']:.4f} | {qual['f1']:.4f} |",
        "",
        "### Per-Sample Detection Breakdown",
        "",
        "| Sample | Lang | Complexity | Expected | Detected | TP | FP | FN | Precision | Recall | F1 |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]

    for s in det["per_sample"]:
        o = s["overall"]
        lines.append(
            f"| `{s['sample_file']}` | {s['language']} | {s['complexity']} | {s['expected_count']} | "
            f"{s['detected_count']} | {o['tp']} | {o['fp']} | {o['fn']} | {o['precision']:.4f} | "
            f"{o['recall']:.4f} | {o['f1']:.4f} |"
        )

    # Missed / False positives detail
    lines.extend(["", "### False Negatives & False Positives Summary", ""])
    any_err = False
    for s in det["per_sample"]:
        if s["false_negatives"] or s["false_positives"]:
            any_err = True
            lines.append(f"- **`{s['sample_file']}`**:")
            if s["false_negatives"]:
                fn_list = ", ".join(f"{e['type']} (lines {e['line_range']})" for e in s["false_negatives"])
                lines.append(f"  - Missed (FN): {fn_list}")
            if s["false_positives"]:
                fp_list = ", ".join(f"{f['title']} (line {f['line']}, {f['cwe'] or f['agent']})" for f in s["false_positives"])
                lines.append(f"  - Extra/Unmatched (FP): {fp_list}")
    if not any_err:
        lines.append("- Zero false positives and zero false negatives across all samples.")

    # 2. Severity Accuracy + Confusion Matrix
    lines.extend([
        "",
        "## 2. Severity Classification Accuracy",
        "",
        f"- **Exact Severity Match:** `{sev['exact_matches']} / {sev['matched_findings']}` (**{sev['accuracy'] * 100:.1f}%**)",
        "",
        "### Confusion Matrix (Rows = Expected, Columns = Predicted)",
        "",
        "| Expected \\ Predicted | CRITICAL | HIGH | MEDIUM | LOW | INFO |",
        "| :--- | :---: | :---: | :---: | :---: | :---: |",
    ])
    cm = sev["confusion_matrix"]
    for exp_s in SEVERITY_LEVELS:
        row_vals = " | ".join(str(cm[exp_s][p]) for p in SEVERITY_LEVELS)
        lines.append(f"| **{exp_s}** | {row_vals} |")

    # 3. Severity Consistency
    lines.extend([
        "",
        "## 3. Severity Consistency (3 Runs per Sample)",
        "",
        f"- **Same Severity Rate:** `{cons['same_severity_count']} / {cons['total_unique_findings']}` (**{cons['same_severity_rate'] * 100:.1f}%**)",
        f"- **Same Severity Score Rate:** `{cons['same_score_count']} / {cons['total_unique_findings']}` (**{cons['same_score_rate'] * 100:.1f}%**)",
    ])

    # 4. Remediation Quality
    lines.extend([
        "",
        "## 4. Remediation Quality",
        "",
        f"- **Total Detected Findings Evaluated:** `{rem['total_findings']}`",
        f"- **Specific Fix Rate (non-generic):** `{rem['specific_count']} / {rem['total_findings']}` (**{rem['specific_rate'] * 100:.1f}%**)",
        f"- **Syntax-Valid Corrected Code Rate:** `{rem['syntax_valid_count']} / {rem['total_findings']}` (**{rem['syntax_valid_rate'] * 100:.1f}%**)",
        f"- **Vulnerable Pattern Removed Rate:** `{rem['pattern_removed_count']} / {rem['total_findings']}` (**{rem['pattern_removed_rate'] * 100:.1f}%**)",
        f"- **Two-Tier Self-Verified Rate:** `{rem['verified_count']} / {rem['total_findings']}` (**{rem['verified_rate'] * 100:.1f}%**)",
    ])
    if rem["failed_items"]:
        fail_by_title = Counter(f"{x['title']} ({x['language']})" for x in rem["failed_items"])
        lines.append("- **Weak / Fallback Remediation Types:** " + ", ".join(f"{k}: {v}" for k, v in fail_by_title.most_common(10)))

    # 5. RAG Retrieval Relevance
    lines.extend([
        "",
        "## 5. RAG Retrieval Relevance",
        "",
        f"- **In-Scope Questions:** `{rag['total_in_scope']}`",
        f"- **Retriever Hit Rate@1:** `{rag['hit_at_1_count']} / {rag['total_in_scope']}` (**{rag['hit_rate_at_1'] * 100:.1f}%**)",
        f"- **Retriever Hit Rate@3:** `{rag['hit_at_3_count']} / {rag['total_in_scope']}` (**{rag['hit_rate_at_3'] * 100:.1f}%**)",
        f"- **Retriever Precision@3:** (**{rag['precision_at_3'] * 100:.1f}%**)",
        f"- **Assistant Grounded Citation Rate:** `{rag['cited_count']} / {rag['total_in_scope']}` (**{rag['citation_rate'] * 100:.1f}%**)",
        f"- **Out-of-Scope Decline Accuracy:** `{rag['out_of_scope_declined']} / {rag['total_out_of_scope']}` (**{rag['out_of_scope_accuracy'] * 100:.1f}%**)",
        "",
        "| QID | Topic | Hit@3 | Grounded | Top-3 Retrieved Sources |",
        "| :--- | :--- | :---: | :---: | :--- |",
    ])
    for q in rag["in_scope_details"]:
        lines.append(
            f"| {q['id']} | {q['topic']} | {'YES' if q['hit_at_3'] else 'NO'} | "
            f"{'YES' if q['assistant_grounded'] else 'NO'} | {', '.join(q['top3_sources'])} |"
        )
    lines.append("")
    for oos in rag["out_of_scope_details"]:
        lines.append(
            f"- **{oos['id']}** (`{oos['question']}`): intent=`{oos['intent']}`, grounded=`{oos['grounded']}`, declined=`{oos['declined_properly']}`"
        )

    # 6. PDF Report Completeness
    lines.extend([
        "",
        "## 6. PDF Report Completeness",
        "",
        f"- **Reports Passed:** `{pdf['passed_reports']} / {pdf['total_reports']}` (**{pdf['pass_rate'] * 100:.1f}%**)",
        "",
        "| Sample | Pages | Valid PDF | All 7 Sections | Count Matches | Non-Empty | Chart Images | Pass |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ])
    for c in pdf["details"]:
        lines.append(
            f"| `{c['filename']}` | {c['page_count']} | {c['valid_header']} | "
            f"{c['all_7_sections_present']} | {c['finding_count_matches']} | "
            f"{c['no_empty_sections']} | {c['embedded_images']} | **{'PASS' if c['passed'] else 'FAIL'}** |"
        )

    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    summary = run_full_evaluation(write_outputs=True)
    ov = summary["detection_accuracy"]["overall"]
    sev = summary["severity_classification"]
    cons = summary["severity_consistency"]
    rem = summary["remediation_quality"]
    rag = summary["rag_relevance"]
    pdf = summary["report_completeness"]

    print("=== Evaluation Complete ===")
    print(f"Detection Overall : P={ov['precision']:.4f} R={ov['recall']:.4f} F1={ov['f1']:.4f} (TP={ov['tp']} FP={ov['fp']} FN={ov['fn']})")
    print(f"  Security        : P={summary['detection_accuracy']['security']['precision']:.4f} R={summary['detection_accuracy']['security']['recall']:.4f} F1={summary['detection_accuracy']['security']['f1']:.4f}")
    print(f"  Code Quality    : P={summary['detection_accuracy']['code_quality']['precision']:.4f} R={summary['detection_accuracy']['code_quality']['recall']:.4f} F1={summary['detection_accuracy']['code_quality']['f1']:.4f}")
    print(f"Severity Accuracy : {sev['exact_matches']}/{sev['matched_findings']} ({sev['accuracy']*100:.1f}%)")
    print(f"Severity Consist. : sev={cons['same_severity_rate']*100:.1f}% score={cons['same_score_rate']*100:.1f}%")
    print(f"Remediation Qual. : specific={rem['specific_rate']*100:.1f}% syntax={rem['syntax_valid_rate']*100:.1f}% removed={rem['pattern_removed_rate']*100:.1f}% verified={rem['verified_rate']*100:.1f}%")
    print(f"RAG Relevance     : hit@1={rag['hit_rate_at_1']*100:.1f}% hit@3={rag['hit_rate_at_3']*100:.1f}% P@3={rag['precision_at_3']*100:.1f}% cited={rag['citation_rate']*100:.1f}% oos={rag['out_of_scope_accuracy']*100:.1f}%")
    print(f"PDF Completeness  : {pdf['passed_reports']}/{pdf['total_reports']} ({pdf['pass_rate']*100:.1f}%)")
    print(f"Saved results to  : {RESULTS_DIR}")

