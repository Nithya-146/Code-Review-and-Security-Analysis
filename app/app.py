"""
AI Code Review & Security Analysis Agent — Streamlit Developer Portal (Milestone 3).

Preserves the Milestone 2 pure-black / deep-navy / bright-blue design and extends it with:
  1. Quick sample code loaders (vulnerable Python & Java samples)
  2. Pipeline progress indicator & friendly validation/error handling
  3. 4-tab layout persisted in st.session_state:
     - Overview: Color-coded Code Health Score gauge, verified fixes count, severity breakdown,
       donut/bar charts, PR executive overview, and top risks
     - Findings: Severity/agent/category/text filters, sorted finding expanders with side-by-side
       Before/After remediations, verification badges, KB references, and line-highlighted code viewer
     - PR Summary: Prioritized fix action table, Markdown/JSON/HTML downloads, full PR markdown report
     - Ask the Assistant: Conversational RAG assistant with session history, grounding indicator,
       expandable KB citations, starter prompts, follow-up buttons, and Clear Chat control
"""

import html
import logging
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── offline mode: skip HuggingFace Hub network checks ──────────────────────
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

# ── sys.path & module resolution fix ───────────────────────────────────────
# When running `streamlit run app/app.py`, Streamlit executes app.py as a script
# and registers `app` in sys.modules as a single-file module (without a __path__).
# If `app` is in sys.modules without __path__, `from app.xyz import ...` raises
# `ModuleNotFoundError: No module named 'app.xyz'; 'app' is not a package`.
# Solution: remove any non-package `app` from sys.modules and ensure PROJECT_ROOT
# is at index 0 of sys.path.
_APP_DIR = Path(__file__).resolve().parent        # …/app/
PROJECT_ROOT = _APP_DIR.parent                    # …/Code Review and Security Analysis/
for _p in (str(_APP_DIR), str(_APP_DIR) + "\\", str(_APP_DIR) + "/"):
    while _p in sys.path:
        sys.path.remove(_p)
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

if "app" in sys.modules and not hasattr(sys.modules["app"], "__path__"):
    del sys.modules["app"]

import streamlit as st

try:
    from app.python_parser import validate_python
    from app.java_parser import validate_java
    from app.schemas import (
        AnalysisResult,
        ChatMessage,
        Finding,
        OWASPCategory,
        ReviewReport,
        SeverityLevel,
    )
except (ImportError, ModuleNotFoundError):
    from python_parser import validate_python
    from java_parser import validate_java
    from schemas import (
        AnalysisResult,
        ChatMessage,
        Finding,
        OWASPCategory,
        ReviewReport,
        SeverityLevel,
    )

try:
    from agents.orchestrator import analyze, create_chat_assistant
except (ImportError, ModuleNotFoundError):
    from orchestrator import analyze, create_chat_assistant

try:
    from app.report import (
        build_report_data,
        generate_markdown_report,
        generate_html_report,
    )
except (ImportError, ModuleNotFoundError):
    from report import (
        build_report_data,
        generate_markdown_report,
        generate_html_report,
    )

try:
    from app.ui_components import (
        MAX_FILE_SIZE_BYTES,
        SEV_COLORS,
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
except (ImportError, ModuleNotFoundError):
    from ui_components import (
        MAX_FILE_SIZE_BYTES,
        SEV_COLORS,
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

logger = logging.getLogger(__name__)

# Human-readable agent names shown in the UI
AGENT_DISPLAY: Dict[str, str] = {
    "security_analysis": "Security Agent",
    "code_analysis": "Code Analysis Agent",
    "remediation_agent": "Remediation Agent",
    "pr_summary_agent": "PR Summary Agent",
}

# ── page config ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI Code Review & Security Analysis Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── global CSS + top-bar hiding ─────────────────────────────────────────────
st.markdown("""
<style>
/* ── page background ───────────────────────────────────────────────── */
html, body, [data-testid="stAppViewContainer"], [data-testid="stApp"] {
    background-color: #000000 !important;
}

/* ── remove top gap left by the hidden header bar ───────────────────── */
[data-testid="stAppViewContainer"] > .main > .block-container {
    padding-top: 0.5rem !important;
}

/* ── hide Streamlit chrome ───────────────────────────────────────────── */
#MainMenu                                 { visibility: hidden; }
footer                                    { visibility: hidden; }
header[data-testid="stHeader"]            { display: none; }
[data-testid="stDecoration"]              { display: none; }
[data-testid="stToolbar"]                 { display: none; }
[data-testid="stAppDeployButton"]         { display: none; }
.stDeployButton                           { display: none; }

/* ── header banner ───────────────────────────────────────────────────── */
.app-banner {
    background: linear-gradient(135deg, #000000 0%, #07101F 55%, #0D1F3C 100%);
    border-bottom: 2px solid #3B82F6;
    padding: 2rem 2rem 1.4rem;
    margin-bottom: 1.6rem;
    border-radius: 0 0 8px 8px;
}
.app-banner h1 {
    margin: 0 0 0.35rem;
    font-size: 1.85rem;
    font-weight: 700;
    color: #E6EDF7;
    letter-spacing: -0.01em;
}
.app-banner p {
    margin: 0;
    font-size: 0.95rem;
    color: #94A3B8;
}

/* ── metric cards ────────────────────────────────────────────────────── */
.metric-card {
    background-color: #07101F;
    border: 1px solid #1E3A5F;
    border-top: 3px solid var(--sev-color, #3B82F6);
    border-radius: 8px;
    padding: 1rem 0.75rem;
    text-align: center;
}
.metric-val {
    font-size: 1.8rem;
    font-weight: 700;
    color: var(--sev-color, #E6EDF7);
    line-height: 1.1;
}
.metric-lbl {
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #64748B;
    margin-top: 0.2rem;
}

/* ── overview summary & risk cards ───────────────────────────────────── */
.overview-card {
    background-color: #07101F;
    border: 1px solid #1E3A5F;
    border-radius: 10px;
    padding: 1.15rem 1.3rem;
    margin-bottom: 0.85rem;
}
.risk-item {
    background-color: #050B14;
    border: 1px solid #1E3A5F;
    border-left: 3px solid #EF4444;
    border-radius: 6px;
    padding: 0.65rem 0.9rem;
    margin-bottom: 0.5rem;
    color: #CBD5E1;
    font-size: 0.88rem;
}

/* ── severity badges ─────────────────────────────────────────────────── */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 9999px;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}
.badge-CRITICAL { background:#3B0A0A; color:#EF4444; border:1px solid #EF4444; }
.badge-HIGH     { background:#431407; color:#F97316; border:1px solid #F97316; }
.badge-MEDIUM   { background:#422006; color:#EAB308; border:1px solid #EAB308; }
.badge-LOW      { background:#0D1F3C; color:#3B82F6; border:1px solid #3B82F6; }
.badge-INFO     { background:#111827; color:#9CA3AF; border:1px solid #374151; }
.badge-CLEAN    { background:#064E3B; color:#10B981; border:1px solid #10B981; }

/* ── report tables ───────────────────────────────────────────────────── */
.report-table {
    width: 100%;
    border-collapse: collapse;
    margin: 0.6rem 0 1rem;
    font-size: 0.88rem;
}
.report-table th, .report-table td {
    padding: 0.55rem 0.75rem;
    border: 1px solid #1E3A5F;
    text-align: left;
}
.report-table th {
    background-color: #0D1F3C;
    color: #E6EDF7;
    font-weight: 600;
}
.report-table td {
    background-color: #07101F;
    color: #E6EDF7;
}
.report-table .num-col {
    text-align: right !important;
    width: 90px;
    font-weight: 600;
}

/* ── section headers ─────────────────────────────────────────────────── */
.section-title {
    font-size: 1rem;
    font-weight: 600;
    color: #94A3B8;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin: 1.4rem 0 0.8rem;
    border-bottom: 1px solid #1E3A5F;
    padding-bottom: 0.4rem;
}

/* ── tabs ────────────────────────────────────────────────────────────── */
div[data-baseweb="tab-list"] {
    gap: 0.5rem;
    border-bottom: 1px solid #1E3A5F;
    padding-bottom: 0.25rem;
}
button[data-baseweb="tab"] {
    background-color: #07101F !important;
    border: 1px solid #1E3A5F !important;
    border-radius: 6px 6px 0 0 !important;
    color: #94A3B8 !important;
    padding: 0.45rem 1.1rem !important;
    font-weight: 600 !important;
}
button[data-baseweb="tab"][aria-selected="true"] {
    background-color: #0D1F3C !important;
    color: #E6EDF7 !important;
    border-color: #3B82F6 !important;
    border-bottom: 2px solid #3B82F6 !important;
}

/* ── primary button ──────────────────────────────────────────────────── */
.stButton > button[kind="primary"] {
    background-color: #3B82F6;
    color: #ffffff;
    border: none;
    font-weight: 600;
    border-radius: 6px;
    padding: 0.5rem 1.6rem;
    transition: box-shadow 0.15s ease;
}
.stButton > button[kind="primary"]:hover {
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.35);
}

/* ── keyboard focus outline ──────────────────────────────────────────── */
*:focus-visible {
    outline: 2px solid #3B82F6 !important;
    outline-offset: 2px !important;
}

/* ── finding detail blocks ───────────────────────────────────────────── */
.finding-header {
    font-size: 1rem;
    font-weight: 600;
    color: #E6EDF7;
    margin-bottom: 0.5rem;
}
.finding-meta {
    font-size: 0.82rem;
    color: #94A3B8;
    margin-bottom: 0.75rem;
}
.rem-card {
    background: #050B14;
    border: 1px solid #1E3A5F;
    border-radius: 8px;
    padding: 0.85rem 1rem;
    margin: 0.65rem 0;
}
.kb-quote {
    border-left: 3px solid #3B82F6;
    background: #07101F;
    padding: 0.65rem 1rem;
    border-radius: 0 6px 6px 0;
    font-size: 0.82rem;
    color: #94A3B8;
    margin-top: 0.4rem;
}
</style>
""", unsafe_allow_html=True)


# ── cached resources & helpers ──────────────────────────────────────────────

@st.cache_resource
def _get_retriever():
    """Loads the KB Retriever once per Streamlit server process."""
    from kb.retriever import retriever_singleton
    return retriever_singleton()


def _safe_get_retriever() -> Optional[Any]:
    """Returns cached KB retriever instance, or None if unavailable offline."""
    try:
        return _get_retriever()
    except Exception:
        return None


def _warm_retriever() -> None:
    """Call at startup so the first submit does not pay the cold-start cost."""
    _safe_get_retriever()


def _severity_str(finding: Any) -> str:
    """Extracts a plain uppercase severity string from a finding dict or object."""
    return extract_severity_str(finding)


def _badge_html(sev: str) -> str:
    """Returns an HTML severity badge."""
    return badge_html(sev)


def _metric_card(label: str, value: Any, color: str) -> str:
    """Returns HTML for a coloured metric card."""
    return (
        f"<div class='metric-card' style='--sev-color:{color};'>"
        f"<div class='metric-val'>{html.escape(str(value))}</div>"
        f"<div class='metric-lbl'>{html.escape(str(label))}</div>"
        f"</div>"
    )


def _clean_evidence_excerpt(raw: str, max_sentences: int = 3) -> str:
    """
    Extracts up to *max_sentences* sentences from a KB evidence string.

    Strips leading source prefix (e.g. '[A05_injection.md]: '),
    removes markdown heading markers (#), and trims whitespace.
    """
    if "]: " in raw:
        raw = raw.split("]: ", 1)[1]

    raw = re.sub(r"^#+\s*", "", raw, flags=re.MULTILINE)
    sentences = re.split(r"(?<=[.!?])\s+", raw.strip())
    return " ".join(s.strip() for s in sentences[:max_sentences] if s.strip())


def _source_from_evidence(raw: str) -> str:
    """Extracts the source filename from '[filename.md]: ...' format."""
    if raw.startswith("[") and "]: " in raw:
        return raw[1:raw.index("]")]
    return "Knowledge Base"


def _owasp_display(val: Any) -> str:
    """
    Converts an OWASPCategory enum or string to a readable display name.

    Example: OWASPCategory.A08  ->  'A08:2025 Software or Data Integrity Failures'
    """
    if val is None:
        return ""
    raw = val.value if hasattr(val, "value") else str(val)
    return raw.replace("-", " ", 1)


def _agent_display(agent: str) -> str:
    """Returns a human-readable agent name."""
    return AGENT_DISPLAY.get(agent, agent.replace("_", " ").title())


# ── sample & chat callbacks ─────────────────────────────────────────────────

def _load_python_sample_cb() -> None:
    """Loads vulnerable Python sample code into session state before widget render."""
    sample_code, sample_name = load_sample_code("python", project_root=PROJECT_ROOT)
    st.session_state["lang_select"] = "Python"
    st.session_state["input_mode_radio"] = "Paste code"
    st.session_state["paste_area"] = sample_code
    st.session_state["sample_filename"] = sample_name
    st.session_state["sample_code_ref"] = sample_code


def _load_java_sample_cb() -> None:
    """Loads vulnerable Java sample code into session state before widget render."""
    sample_code, sample_name = load_sample_code("java", project_root=PROJECT_ROOT)
    st.session_state["lang_select"] = "Java"
    st.session_state["input_mode_radio"] = "Paste code"
    st.session_state["paste_area"] = sample_code
    st.session_state["sample_filename"] = sample_name
    st.session_state["sample_code_ref"] = sample_code


def _queue_chat_question(question: str) -> None:
    """Queues a starter or follow-up question for immediate execution."""
    st.session_state["pending_chat_question"] = question


def _clear_chat_cb() -> None:
    """Clears conversation history and any pending chat question."""
    st.session_state["chat_history"] = []
    st.session_state.pop("pending_chat_question", None)


# ── pipeline runner ─────────────────────────────────────────────────────────

def _execute_analysis_pipeline(
    code: str,
    lang_key: str,
    upload_filename: str,
    upload_error: Optional[str] = None,
) -> None:
    """Validates input, executes the multi-agent pipeline with progress feedback, and caches results."""
    if upload_error:
        st.error(upload_error)
        return

    is_ok, val_err = validate_submission_input(code, lang_key)
    if not is_ok:
        st.warning(val_err or "⚠️ Nothing to analyze. Please upload or paste valid code first.")
        return

    progress_bar = st.progress(10, text="Validating submission syntax…")
    try:
        vr = validate_python(code) if lang_key == "python" else validate_java(code)
    except Exception as exc:
        progress_bar.empty()
        logger.exception("Unexpected error during syntax validation")
        st.error(
            f"❌ Could not validate source syntax ({type(exc).__name__}). "
            "Please verify the uploaded code matches the selected language."
        )
        return

    if not vr.get("is_valid", False):
        progress_bar.empty()
        st.error("❌ Syntax error — please fix before running analysis.")
        st.error(vr.get("error", "Unknown syntax error."))
        return

    try:
        sub_id = f"SUB-{uuid.uuid4().hex[:8].upper()}"
        report = ReviewReport(
            submission_id=sub_id,
            language=lang_key,
            is_valid_syntax=True,
            ast_metadata=vr.get("metadata", {}),
            security_findings=[],
            quality_findings=[],
            remediations=[],
            pr_summary_markdown=None,
        )

        progress_bar.progress(35, text="Running parallel Code Analysis & Security agents…")
        result: AnalysisResult = analyze(
            code,
            language=lang_key,
            filename=upload_filename,
        )

        progress_bar.progress(80, text="Finalizing remediations, PR summary & assistant context…")
        report.findings = result.findings
        report.remediations = result.remediations
        if result.pr_summary:
            report.pr_summary_markdown = result.pr_summary.markdown

        st.session_state["analysis_result"] = result.model_dump()
        st.session_state["review_report"] = report.model_dump()
        st.session_state["current_code"] = code
        st.session_state["lang_key"] = lang_key
        st.session_state["upload_filename"] = upload_filename
        st.session_state["chat_history"] = []
        st.session_state.pop("pending_chat_question", None)

        progress_bar.progress(100, text="Analysis complete!")
        progress_bar.empty()

        for agent_name, status in result.run_status.items():
            if status != "SUCCESS":
                friendly_msg = str(status).splitlines()[0][:180]
                st.warning(f"⚠️ **{_agent_display(agent_name)}**: {friendly_msg}")

        st.success(f"✅ Analysis complete — {len(result.findings)} finding(s) found in `{upload_filename}`.")
    except Exception as exc:
        progress_bar.empty()
        logger.exception("Code review pipeline failed unexpectedly")
        st.error(
            f"⚠️ Analysis pipeline encountered an unexpected error ({type(exc).__name__}). "
            "Please check your code input and try again."
        )


# ── tab renderers ───────────────────────────────────────────────────────────

def _render_overview_tab(
    res: Dict[str, Any],
    report_data: Dict[str, Any],
) -> None:
    """Renders Tab 1: Health Score gauge, verified fix count, severity metrics/charts, PR overview."""
    findings: List[Dict[str, Any]] = res.get("findings", [])
    remediations: List[Dict[str, Any]] = res.get("remediations", [])
    pr_summary: Optional[Dict[str, Any]] = res.get("pr_summary")
    hs: Optional[Dict[str, Any]] = res.get("health_score")

    sev_counts = get_severity_counts(findings)
    verified_cnt, total_rem_cnt = get_verified_remediation_counts(remediations)

    if isinstance(hs, dict) and "score" in hs:
        score = int(hs.get("score", 100))
        grade = str(hs.get("grade", get_health_grade(score)))
    else:
        score = 100 if not findings else max(0, 100 - len(findings) * 5)
        grade = get_health_grade(score)

    score_color = get_health_score_color(score)

    # ── Top Row: Gauge + Executive Overview & Top Risks ───────────────────
    col_gauge, col_summary = st.columns([1, 2])

    with col_gauge:
        st.markdown(build_health_gauge_svg(score, grade), unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)

        if total_rem_cnt > 0:
            rem_color = "#10B981" if verified_cnt == total_rem_cnt else "#EAB308"
            rem_label = f"{verified_cnt} of {total_rem_cnt} fixes verified"
        elif not findings:
            rem_color = "#10B981"
            rem_label = "0 of 0 fixes verified (Clean)"
        else:
            rem_color = "#64748B"
            rem_label = "0 automated fixes available"

        st.markdown(
            f"<div class='metric-card' style='--sev-color:{rem_color};padding:0.85rem;'>"
            f"<div style='font-size:1.15rem;font-weight:700;color:{rem_color};'>{html.escape(rem_label)}</div>"
            f"<div class='metric-lbl'>Automated Remediation Verification</div>"
            f"</div>",
            unsafe_allow_html=True,
        )

    with col_summary:
        r_level = report_data.get("risk_level", "Low")
        r_badge_cls = "badge-CLEAN" if r_level == "No issues found" else f"badge-{r_level.upper()}"

        exec_text = (
            pr_summary.get("executive_overview")
            if isinstance(pr_summary, dict) and pr_summary.get("executive_overview")
            else report_data.get("risk_reason", "")
        )

        st.markdown(
            f"<div class='overview-card' style='border-left:4px solid {score_color};'>"
            f"<div style='display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:0.5rem;margin-bottom:0.55rem;'>"
            f"<strong style='color:#E6EDF7;font-size:1rem;'>Executive Overview</strong>"
            f"<span class='badge {r_badge_cls}'>Risk: {html.escape(str(r_level).upper())}</span>"
            f"</div>"
            f"<p style='color:#CBD5E1;font-size:0.92rem;margin:0;'>{html.escape(str(exec_text))}</p>"
            f"</div>",
            unsafe_allow_html=True,
        )

        top_risks: List[str] = (
            pr_summary.get("top_risks", [])
            if isinstance(pr_summary, dict)
            else []
        )
        st.markdown("#### ⚠️ Top Risks")
        if top_risks:
            for risk in top_risks:
                st.markdown(
                    f"<div class='risk-item'>{html.escape(str(risk))}</div>",
                    unsafe_allow_html=True,
                )
        else:
            st.success("🎉 No critical or high-severity risks detected.")

    # ── File metadata strip (preserved from Milestone 2) ──────────────────
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Target File", report_data["filename"])
    with m2:
        st.metric("Language", str(report_data["language"]).capitalize())
    with m3:
        st.metric("Lines of Code", report_data["lines_of_code"])
    with m4:
        st.metric("Total Findings", report_data["total_findings"])

    # ── Severity Breakdown Metric Cards ───────────────────────────────────
    st.markdown("<div class='section-title'>Severity Breakdown</div>", unsafe_allow_html=True)
    cols = st.columns(6)
    cards = [
        ("CRITICAL", sev_counts["CRITICAL"], SEV_COLORS["CRITICAL"]),
        ("HIGH",     sev_counts["HIGH"],     SEV_COLORS["HIGH"]),
        ("MEDIUM",   sev_counts["MEDIUM"],   SEV_COLORS["MEDIUM"]),
        ("LOW",      sev_counts["LOW"],      SEV_COLORS["LOW"]),
        ("INFO",     sev_counts["INFO"],     SEV_COLORS["INFO"]),
        ("TOTAL",    sev_counts["TOTAL"],    "#3B82F6"),
    ]
    for col, (label, val, color) in zip(cols, cards):
        with col:
            st.markdown(_metric_card(label, val, color), unsafe_allow_html=True)

    # ── Severity Visualizations (Donut + Bar Chart) ───────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    col_donut, col_bar = st.columns([1, 1])
    with col_donut:
        st.markdown(build_severity_donut_svg(sev_counts), unsafe_allow_html=True)
    with col_bar:
        non_zero = {
            k: sev_counts[k]
            for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            if sev_counts.get(k, 0) > 0
        }
        if non_zero:
            st.bar_chart(non_zero, color="#3B82F6")
        else:
            st.success("🎉 No issues found — code is clean.")


def _render_findings_tab(
    res: Dict[str, Any],
    code_text: str,
    display_lang: str,
) -> None:
    """Renders Tab 2: Filters, sorted findings expanders with Before/After diffs, highlighted viewer."""
    findings: List[Dict[str, Any]] = res.get("findings", [])
    remediations: List[Dict[str, Any]] = res.get("remediations", [])
    rem_map = map_remediations_by_finding(remediations)

    if not findings:
        st.success("🎉 No security vulnerabilities or code quality issues were detected.")
        if code_text.strip():
            st.markdown("<div class='section-title'>Submitted Code Viewer</div>", unsafe_allow_html=True)
            st.markdown(build_code_viewer_html(code_text, []), unsafe_allow_html=True)
        return

    sev_counts = get_severity_counts(findings)
    st.markdown("<div class='section-title'>Filter &amp; Explore Findings</div>", unsafe_allow_html=True)

    f1, f2, f3, f4 = st.columns([1.2, 1.1, 1.1, 1.3])
    with f1:
        active_sevs = [s for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] if sev_counts.get(s, 0) > 0]
        sel_sevs: List[str] = st.multiselect(
            "Severity",
            options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            default=active_sevs,
            key="filter_severity",
        )
    with f2:
        all_agents = sorted({str(f.get("agent", "")) for f in findings if f.get("agent")})
        sel_agents: List[str] = st.multiselect(
            "Agent",
            options=all_agents,
            default=all_agents,
            format_func=_agent_display,
            key="filter_agent",
        )
    with f3:
        all_categories = sorted({str(f.get("category", "General") or "General") for f in findings})
        sel_cats: List[str] = st.multiselect(
            "Category",
            options=all_categories,
            default=all_categories,
            key="filter_category",
        )
    with f4:
        search_query: str = st.text_input(
            "Text search",
            placeholder="Title, CWE, line, code…",
            key="filter_search",
        )

    filtered = filter_findings(
        findings,
        severities=sel_sevs,
        agents=sel_agents,
        categories=sel_cats,
        search_text=search_query,
    )
    displayed = sort_findings(filtered, sort_by="severity")
    st.caption(f"Showing **{len(displayed)}** of **{len(findings)}** finding(s) (sorted by severity)")

    # ── Findings Expanders ────────────────────────────────────────────────
    for f in displayed:
        fid = str(f.get("id", ""))
        sev = _severity_str(f)
        title = str(f.get("title", "Finding"))
        l_start = int(f.get("line_start", 1) or 1)
        l_end = int(f.get("line_end", l_start) or l_start)
        agent_raw = str(f.get("agent", ""))
        category = str(f.get("category", ""))
        score = float(f.get("severity_score", 0.0) or 0.0)
        confidence = float(f.get("confidence", 1.0) or 0.0)
        snippet = str(f.get("code_snippet") or "")
        explanation = str(f.get("explanation") or "")
        suggestion = str(f.get("suggestion") or "")
        evidence = str(f.get("evidence") or "")
        owasp_raw = f.get("owasp_category")
        cwe_id = str(f.get("cwe_id") or "")
        filename = str(f.get("file") or st.session_state.get("upload_filename", ""))

        line_label = f"Line {l_start}" if l_start == l_end else f"Lines {l_start}–{l_end}"
        exp_title = f"[{sev}] {title} — {line_label} ({_agent_display(agent_raw)})"

        with st.expander(exp_title, expanded=False):
            st.markdown(
                f"{_badge_html(sev)} &nbsp; <span class='finding-header'>{html.escape(title)}</span> &nbsp;"
                f"<span style='color:#64748B;font-size:0.82rem'>{html.escape(line_label)}"
                f"{' · ' + html.escape(filename) if filename else ''}</span>",
                unsafe_allow_html=True,
            )

            st.markdown(
                f"<div class='finding-meta'>"
                f"ID: <strong style='color:#E6EDF7'>{html.escape(fid or 'N/A')}</strong> &nbsp;|&nbsp; "
                f"Agent: <strong style='color:#E6EDF7'>{html.escape(_agent_display(agent_raw))}</strong> &nbsp;|&nbsp; "
                f"Category: <strong style='color:#E6EDF7'>{html.escape(category or 'General')}</strong> &nbsp;|&nbsp; "
                f"CVSS Score: <strong style='color:#E6EDF7'>{score:.1f}</strong> &nbsp;|&nbsp; "
                f"Confidence: <strong style='color:#E6EDF7'>{confidence:.0%}</strong>"
                f"</div>",
                unsafe_allow_html=True,
            )

            owasp_text = _owasp_display(owasp_raw)
            if owasp_text or cwe_id:
                parts = []
                if owasp_text:
                    parts.append(f"**OWASP:** {owasp_text}")
                if cwe_id:
                    parts.append(f"**CWE:** {cwe_id}")
                st.markdown("  &nbsp;|&nbsp;  ".join(parts))

            if explanation.strip():
                st.markdown("**Description:**")
                st.write(explanation)

            rem = rem_map.get(fid)
            if rem:
                is_verified = bool(rem.get("verified", False))
                ver_note = str(rem.get("verification_note", "")).strip()
                rem_conf = float(rem.get("confidence", 0.0) or 0.0)
                fix_summary = str(rem.get("fix_summary", "")).strip()
                rem_expl = str(rem.get("explanation", "")).strip()
                orig_code = str(rem.get("original_code") or snippet or "").strip()
                corr_code = str(rem.get("corrected_code") or "").strip()
                best_practice = str(rem.get("best_practice") or "").strip()
                kb_refs: List[str] = list(rem.get("references") or [])

                st.markdown("<div class='section-title' style='margin-top:0.8rem;'>Automated Remediation</div>", unsafe_allow_html=True)
                st.markdown(
                    f"<div class='rem-card'>"
                    f"{verified_badge_html(is_verified)} &nbsp; "
                    f"<span style='color:#94A3B8;font-size:0.82rem;'>Fix Confidence: "
                    f"<strong style='color:#E6EDF7;'>{rem_conf:.0%}</strong></span><br>"
                    f"<span style='color:#CBD5E1;font-size:0.85rem;display:inline-block;margin-top:0.4rem;'>"
                    f"<strong>Verification Note:</strong> {html.escape(ver_note or 'Completed')}</span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )

                if rem_expl and rem_expl.lower() != explanation.strip().lower():
                    st.markdown("**Why It Is a Problem:**")
                    st.write(rem_expl)

                if fix_summary:
                    st.markdown(f"**Fix Summary:** {fix_summary}")

                if orig_code or corr_code:
                    col_b, col_a = st.columns(2)
                    with col_b:
                        st.markdown("**❌ Before (Vulnerable Code)**")
                        st.code(orig_code or "# See highlighted lines below", language=display_lang)
                    with col_a:
                        st.markdown("**✅ After (Recommended Fix)**")
                        st.code(corr_code or "# Manual remediation required", language=display_lang)

                if best_practice:
                    st.markdown("**💡 Best Practice:**")
                    st.info(best_practice)

                if kb_refs:
                    ref_list = ", ".join(f"`{r}`" for r in kb_refs)
                    st.markdown(f"**📚 Knowledge Base References:** {ref_list}")
            else:
                if snippet.strip():
                    st.markdown("**Code snippet:**")
                    st.code(snippet, language=display_lang)
                if suggestion.strip():
                    st.markdown("**Suggested fix:**")
                    st.info(suggestion)

            if evidence.strip() and not (rem and rem.get("references")):
                src = _source_from_evidence(evidence)
                excerpt = _clean_evidence_excerpt(evidence)
                st.markdown(f"**Knowledge base — `{src}`:**")
                st.markdown(f"<div class='kb-quote'>{html.escape(excerpt)}</div>", unsafe_allow_html=True)

    # ── Highlighted Vulnerable Lines Code Viewer ──────────────────────────
    st.markdown(
        "<div class='section-title'>Source Code Viewer — Highlighted Vulnerable Lines</div>",
        unsafe_allow_html=True,
    )
    st.caption(f"Highlighting line matches for {len(displayed)} currently visible finding(s).")
    st.markdown(build_code_viewer_html(code_text, displayed), unsafe_allow_html=True)


def _render_pr_summary_tab(
    res: Dict[str, Any],
    report_data: Dict[str, Any],
) -> None:
    """Renders Tab 3: Prioritized fix list table, download buttons, and PR markdown report."""
    pr_summary: Optional[Dict[str, Any]] = res.get("pr_summary")
    prioritized_fixes: List[Dict[str, Any]] = (
        pr_summary.get("prioritized_fixes", [])
        if isinstance(pr_summary, dict)
        else []
    )

    st.markdown("<div class='section-title'>Prioritized Action Plan</div>", unsafe_allow_html=True)
    st.markdown(build_prioritized_fixes_table_html(prioritized_fixes), unsafe_allow_html=True)

    # ── Export Downloads ──────────────────────────────────────────────────
    st.markdown("<div class='section-title'>Export Reports</div>", unsafe_allow_html=True)
    pr_md_text = export_pr_markdown(res)
    json_results_text = export_results_json(res)
    html_report_text = generate_html_report(report_data)
    base_name = Path(str(report_data.get("filename", "submission"))).stem

    col_dl1, col_dl2, col_dl3 = st.columns(3)
    with col_dl1:
        st.download_button(
            label="📄 Download Markdown Report (.md)",
            data=pr_md_text,
            file_name=f"pr_summary_{base_name}.md",
            mime="text/markdown",
            use_container_width=True,
            key="dl_pr_markdown",
        )
    with col_dl2:
        st.download_button(
            label="📦 Download Full Results (.json)",
            data=json_results_text,
            file_name=f"analysis_results_{base_name}.json",
            mime="application/json",
            use_container_width=True,
            key="dl_full_json",
        )
    with col_dl3:
        st.download_button(
            label="🌐 Download HTML Report (.html)",
            data=html_report_text,
            file_name=f"report_{base_name}.html",
            mime="text/html",
            use_container_width=True,
            key="dl_html_report",
        )

    # ── Rendered PR-Style Markdown Report ─────────────────────────────────
    st.markdown("<div class='section-title'>Pull Request Review Report</div>", unsafe_allow_html=True)
    st.markdown(pr_md_text)

    # ── Milestone 2 Detailed Security & Quality Tables ────────────────────
    with st.expander("📊 Detailed OWASP Security & Code Quality Tables", expanded=False):
        sec_data = report_data.get("security_summary", {})
        qual_data = report_data.get("quality_summary", {})
        col_sec, col_qual = st.columns(2)
        with col_sec:
            st.markdown("#### 🔒 Security Summary")
            if sec_data:
                sec_rows = "".join(
                    f"<tr><td>{html.escape(str(cat))}</td><td class='num-col'>{cnt}</td></tr>"
                    for cat, cnt in sec_data.items()
                )
                st.markdown(
                    f"<table class='report-table'>"
                    f"<thead><tr><th>OWASP Category</th><th class='num-col'>Findings</th></tr></thead>"
                    f"<tbody>{sec_rows}</tbody></table>",
                    unsafe_allow_html=True,
                )
            else:
                st.caption("No security vulnerabilities detected.")

        with col_qual:
            st.markdown("#### 🧹 Code Quality Summary")
            if qual_data:
                qual_rows = "".join(
                    f"<tr><td>{html.escape(str(cat))}</td><td class='num-col'>{cnt}</td></tr>"
                    for cat, cnt in qual_data.items()
                )
                st.markdown(
                    f"<table class='report-table'>"
                    f"<thead><tr><th>Quality Category</th><th class='num-col'>Findings</th></tr></thead>"
                    f"<tbody>{qual_rows}</tbody></table>",
                    unsafe_allow_html=True,
                )
            else:
                st.caption("No code quality defects detected.")


def _process_chat_turn(
    question: str,
    res: Optional[Dict[str, Any]],
    code_text: str,
    lang_key: str,
) -> None:
    """Runs ChatAssistant via create_chat_assistant and appends turn to session history."""
    clean_q = (question or "").strip()
    if not clean_q:
        return

    history_dicts: List[Dict[str, Any]] = st.session_state.setdefault("chat_history", [])
    prior_messages = [
        ChatMessage(role=m["role"], content=m["content"])
        for m in history_dicts
        if isinstance(m, dict) and m.get("role") in ("user", "assistant") and m.get("content")
    ]

    history_dicts.append({"role": "user", "content": clean_q})

    try:
        has_analysis = isinstance(res, dict) and "findings" in res
        if has_analysis:
            result_obj = AnalysisResult.model_validate(res)
        else:
            result_obj = AnalysisResult(
                findings=[],
                counts_by_severity={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                counts_by_agent={"code_analysis": 0, "security_analysis": 0},
                language=lang_key,
                filename="not_analyzed_yet",
            )

        assistant = create_chat_assistant(
            result=result_obj,
            code=code_text or "",
            language=lang_key,
            retriever=_safe_get_retriever(),
        )
        resp = assistant.ask(clean_q, history=prior_messages)

        answer_text = resp.answer
        follow_ups = list(resp.follow_up_suggestions or [])

        if not has_analysis and resp.intent in ("finding_explanation", "fix_request", "summary_request"):
            if not resp.grounded:
                answer_text = (
                    "No code has been analyzed yet. Please upload/paste code or load a sample above "
                    "and click **🔍 Analyze code** to inspect findings and fixes for a specific file.\n\n"
                    "Meanwhile, I can answer general secure coding and OWASP Top 10 questions!\n\n"
                    + resp.answer
                )
                follow_ups = [
                    "What is SQL injection and how do I prevent it?",
                    "What are best practices for API key storage?",
                    "What is Cross-Site Scripting (XSS)?",
                ]

        history_dicts.append(
            {
                "role": "assistant",
                "content": answer_text,
                "grounded": bool(resp.grounded),
                "intent": str(resp.intent),
                "related_finding_ids": list(resp.related_finding_ids or []),
                "citations": [c.model_dump() for c in (resp.citations or [])],
                "follow_up_suggestions": follow_ups,
            }
        )
    except Exception as exc:
        logger.exception("Conversational assistant failed to answer query")
        history_dicts.append(
            {
                "role": "assistant",
                "content": (
                    f"⚠️ I encountered an error while answering that question ({type(exc).__name__}). "
                    "Please try rephrasing or ask another security or code review question."
                ),
                "grounded": False,
                "intent": "error",
                "related_finding_ids": [],
                "citations": [],
                "follow_up_suggestions": [],
            }
        )


def _render_assistant_tab(
    res: Optional[Dict[str, Any]],
    code_text: str,
    lang_key: str,
) -> None:
    """Renders Tab 4: RAG Conversational Code Assistant with citations & follow-ups."""
    st.session_state.setdefault("chat_history", [])
    has_analysis = isinstance(res, dict) and "findings" in res
    findings: List[Dict[str, Any]] = res.get("findings", []) if has_analysis else []

    head_col, btn_col = st.columns([4, 1])
    with head_col:
        st.markdown("#### 💬 RAG Conversational Code Assistant")
        if not has_analysis:
            st.info(
                "No code has been analyzed yet — upload/paste code above to ask about specific lines or fixes, "
                "or ask general OWASP / secure coding questions right now!"
            )
    with btn_col:
        st.button(
            "🗑️ Clear chat",
            key="clear_chat_btn",
            on_click=_clear_chat_cb,
            use_container_width=True,
        )

    # Process queued starter / follow-up question OR chat_input before rendering history
    queued_prompt: Optional[str] = st.session_state.pop("pending_chat_question", None)
    typed_prompt: Optional[str] = st.chat_input(
        "Ask about findings, line numbers, fixes, or security best practices…",
        key="assistant_chat_input",
    )
    active_prompt = queued_prompt or typed_prompt
    if active_prompt:
        _process_chat_turn(active_prompt, res=res, code_text=code_text, lang_key=lang_key)

    chat_history: List[Dict[str, Any]] = st.session_state.get("chat_history", [])

    # ── Starter Questions (only before first message) ─────────────────────
    if not chat_history:
        if has_analysis and findings:
            first_line = int(findings[0].get("line_start", 1) or 1)
            starters = [
                "What should I fix first?",
                f"Why is line {first_line} flagged?",
                "How do I fix finding 1?",
                "What is OWASP Injection best practice?",
            ]
        elif has_analysis:
            starters = [
                "Summarize the review findings",
                "What is the Code Health Score?",
                "What are best practices for secure error handling?",
            ]
        else:
            starters = [
                "What is SQL injection?",
                "What are best practices for storing secrets?",
                "Explain Cross-Site Scripting (XSS)",
            ]

        st.caption("Suggested starter questions:")
        s_cols = st.columns(len(starters))
        for idx, q_text in enumerate(starters):
            with s_cols[idx]:
                st.button(
                    q_text,
                    key=f"starter_{idx}",
                    on_click=_queue_chat_question,
                    args=(q_text,),
                    use_container_width=True,
                )

    # ── Conversation History ──────────────────────────────────────────────
    last_assistant_idx = max(
        (i for i, m in enumerate(chat_history) if m.get("role") == "assistant"),
        default=-1,
    )

    for idx, msg in enumerate(chat_history):
        role = msg.get("role", "assistant")
        content = msg.get("content", "")

        with st.chat_message(role):
            if role == "assistant":
                grounded = bool(msg.get("grounded", False))
                intent = str(msg.get("intent", "")).replace("_", " ").title()
                st.markdown(
                    f"{grounding_badge_html(grounded)} &nbsp; "
                    f"<span style='color:#64748B;font-size:0.76rem;'>Intent: {html.escape(intent)}</span>",
                    unsafe_allow_html=True,
                )

            st.markdown(content)

            if role == "assistant":
                citations: List[Dict[str, Any]] = msg.get("citations") or []
                if citations:
                    with st.expander(f"📚 Citations ({len(citations)})", expanded=False):
                        for cite in citations:
                            c_src = html.escape(str(cite.get("source", "Knowledge Base")))
                            c_sec = html.escape(str(cite.get("section", "")))
                            c_score = float(cite.get("relevance_score", 0.0) or 0.0)
                            c_snip = html.escape(str(cite.get("snippet", "")))
                            sec_txt = f" · {c_sec}" if c_sec else ""
                            st.markdown(
                                f"<div class='kb-quote'>"
                                f"<strong style='color:#E6EDF7;'>{c_src}</strong>"
                                f"<span style='color:#64748B;'>{sec_txt} (score {c_score:.2f})</span><br>"
                                f"{c_snip}"
                                f"</div>",
                                unsafe_allow_html=True,
                            )

                follow_ups: List[str] = msg.get("follow_up_suggestions") or []
                if idx == last_assistant_idx and follow_ups:
                    st.caption("Suggested follow-ups:")
                    f_cols = st.columns(min(3, len(follow_ups)))
                    for s_idx, sug in enumerate(follow_ups[:3]):
                        with f_cols[s_idx]:
                            st.button(
                                sug,
                                key=f"followup_{idx}_{s_idx}",
                                on_click=_queue_chat_question,
                                args=(sug,),
                                use_container_width=True,
                            )


# ── warm the retriever at startup ───────────────────────────────────────────
_warm_retriever()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 — HEADER BANNER
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="app-banner">
  <h1>🛡️ AI Code Review &amp; Security Analysis Agent</h1>
  <p>Submit Python or Java code for multi-agent quality &amp; vulnerability scanning,
     self-verified automated fixes, PR health scoring, and RAG-grounded Q&amp;A.</p>
</div>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 — CODE INPUT & SAMPLE LOADER
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("<div class='section-title'>Code Input</div>", unsafe_allow_html=True)

st.session_state.setdefault("lang_select", "Python")
st.session_state.setdefault("input_mode_radio", "Upload file")

col_lang, col_mode = st.columns([1, 3])
with col_lang:
    language_choice: str = st.selectbox(
        "Language",
        ["Python", "Java"],
        key="lang_select",
        help="Auto-detected from uploaded file extension or loaded sample; override if needed.",
    )
lang_key: str = "python" if language_choice == "Python" else "java"

with col_mode:
    input_mode: str = st.radio(
        "Input method",
        ["Upload file", "Paste code"],
        horizontal=True,
        label_visibility="collapsed",
        key="input_mode_radio",
    )

# Sample Code Loader
sample_col1, sample_col2, _ = st.columns([1.4, 1.4, 2.2])
with sample_col1:
    st.button(
        "🐍 Load vulnerable Python sample",
        key="load_py_sample_btn",
        on_click=_load_python_sample_cb,
        use_container_width=True,
    )
with sample_col2:
    st.button(
        "☕ Load vulnerable Java sample",
        key="load_java_sample_btn",
        on_click=_load_java_sample_cb,
        use_container_width=True,
    )

uploaded_code: Optional[str] = None
upload_filename: str = f"submission.{'py' if lang_key == 'python' else 'java'}"
upload_error_msg: Optional[str] = None

if input_mode == "Upload file":
    uploaded_file = st.file_uploader(
        "Upload a .py or .java file (max 1 MB)",
        type=["py", "java"],
        key="file_uploader_widget",
    )
    if uploaded_file is not None:
        if uploaded_file.size > MAX_FILE_SIZE_BYTES:
            upload_error_msg = (
                f"❌ File exceeds 1 MB ({uploaded_file.size / 1024 / 1024:.2f} MB)."
            )
            st.error(upload_error_msg)
        else:
            ext = Path(uploaded_file.name).suffix.lower()
            if ext not in (".py", ".java"):
                upload_error_msg = (
                    f"❌ Unsupported extension '{ext}'. Only .py and .java are accepted."
                )
                st.error(upload_error_msg)
            else:
                lang_key = "python" if ext == ".py" else "java"
                upload_filename = uploaded_file.name
                raw = uploaded_file.read()
                try:
                    uploaded_code = raw.decode("utf-8")
                except UnicodeDecodeError:
                    uploaded_code = raw.decode("latin-1")
                    st.warning("⚠️ File is not UTF-8; decoded with Latin-1 fallback.")
                st.info(f"📄 `{uploaded_file.name}` — {len(uploaded_code.splitlines())} lines")
else:
    pasted = st.text_area(
        "Paste source code",
        height=260,
        placeholder="Paste your Python or Java code here…",
        key="paste_area",
    )
    if pasted.strip():
        uploaded_code = pasted
        if pasted == st.session_state.get("sample_code_ref"):
            upload_filename = st.session_state.get("sample_filename", upload_filename)
        else:
            if any(tok in pasted for tok in ("public class", "System.out", "import java.")):
                lang_key = "java"
            upload_filename = f"submission.{'py' if lang_key == 'python' else 'java'}"

if uploaded_code:
    with st.expander("👀 Code preview", expanded=False):
        st.code(uploaded_code, language=lang_key, line_numbers=True)

analyze_clicked: bool = st.button(
    "🔍 Analyze code",
    type="primary",
    use_container_width=False,
    key="analyze_btn",
)

if analyze_clicked:
    _execute_analysis_pipeline(
        code=uploaded_code or "",
        lang_key=lang_key,
        upload_filename=upload_filename,
        upload_error=upload_error_msg,
    )


# ═══════════════════════════════════════════════════════════════════════════
# SECTIONS 3 — TABBED RESULTS & CONVERSATIONAL ASSISTANT
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("<div class='section-title'>Analysis Workspace</div>", unsafe_allow_html=True)

tab_overview, tab_findings, tab_pr, tab_chat = st.tabs([
    "📊 Overview",
    "🔍 Findings",
    "📋 PR Summary",
    "💬 Ask the Assistant",
])

cached_res: Optional[Dict[str, Any]] = st.session_state.get("analysis_result")
cached_code: str = st.session_state.get("current_code", "")
cached_lang: str = st.session_state.get(
    "lang_key",
    cached_res.get("language", lang_key) if isinstance(cached_res, dict) else lang_key,
)

if isinstance(cached_res, dict) and "findings" in cached_res:
    target_file = st.session_state.get("upload_filename", cached_res.get("filename", "unknown"))
    loc_calc = len(cached_code.splitlines()) if cached_code else None
    report_data = build_report_data(
        cached_res,
        lines_of_code=loc_calc,
        filename=target_file,
        language=cached_lang,
    )
else:
    report_data = None

with tab_overview:
    if isinstance(cached_res, dict) and report_data is not None:
        _render_overview_tab(cached_res, report_data)
    else:
        st.info("Submit Python or Java code (or click a sample loader above) and press **🔍 Analyze code** to view the Health Score, severity breakdown, and top risks.")

with tab_findings:
    if isinstance(cached_res, dict):
        _render_findings_tab(cached_res, code_text=cached_code, display_lang=cached_lang)
    else:
        st.info("Findings, side-by-side Before/After fixes, verification badges, and vulnerable line highlights will appear here after analysis.")

with tab_pr:
    if isinstance(cached_res, dict) and report_data is not None:
        _render_pr_summary_tab(cached_res, report_data)
    else:
        st.info("Prioritized action plan, PR review markdown report, and downloadable exports will appear here after analysis.")

with tab_chat:
    _render_assistant_tab(cached_res, code_text=cached_code, lang_key=cached_lang)
