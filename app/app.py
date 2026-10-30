"""
AI Code Review & Security Analysis Agent — Streamlit UI (Milestone 2).

Single-page layout (no sidebar):
  1. Header banner
  2. Code input  (language selector + file upload / paste + Analyze button)
  3. Severity summary  (metric cards + bar chart)
  4. Findings table   (severity badge + title + line + agent + confidence)
  5. Finding details  (one expander per finding)

Redesigned with a pure-black / deep-navy / bright-blue theme.
"""

import os
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
    from app.schemas import AnalysisResult, Finding, OWASPCategory, ReviewReport, SeverityLevel
except (ImportError, ModuleNotFoundError):
    from python_parser import validate_python
    from java_parser import validate_java
    from schemas import AnalysisResult, Finding, OWASPCategory, ReviewReport, SeverityLevel

try:
    from agents.orchestrator import analyze
except (ImportError, ModuleNotFoundError):
    from orchestrator import analyze

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

# ── constants ───────────────────────────────────────────────────────────────
MAX_FILE_SIZE_BYTES: int = 1 * 1024 * 1024  # 1 MB

# Human-readable agent names shown in the UI
AGENT_DISPLAY: Dict[str, str] = {
    "security_analysis": "Security Agent",
    "code_analysis": "Code Analysis Agent",
}

# Colours per severity (dark-theme readable)
SEV_COLORS: Dict[str, str] = {
    "CRITICAL": "#EF4444",  # red
    "HIGH":     "#F97316",  # orange
    "MEDIUM":   "#EAB308",  # amber
    "LOW":      "#3B82F6",  # blue
    "INFO":     "#6B7280",  # gray
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
    margin: 1.6rem 0 0.8rem;
    border-bottom: 1px solid #1E3A5F;
    padding-bottom: 0.4rem;
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


# ── helpers ─────────────────────────────────────────────────────────────────

@st.cache_resource
def _get_retriever():
    """Loads the KB Retriever once per Streamlit server process."""
    from kb.retriever import retriever_singleton
    return retriever_singleton()


def _warm_retriever() -> None:
    """Call at startup so the first submit does not pay the cold-start cost."""
    try:
        _get_retriever()
    except Exception:
        pass  # KB unavailable; SecurityAgent runs without RAG evidence.


def _severity_str(finding: Dict[str, Any]) -> str:
    """Extracts a plain severity string from a finding dict."""
    raw = finding.get("severity", "INFO")
    return raw.value if hasattr(raw, "value") else str(raw).split(".")[-1]


def _badge_html(sev: str) -> str:
    """Returns an HTML severity badge."""
    return f"<span class='badge badge-{sev}'>{sev}</span>"


def _metric_card(label: str, value: int, color: str) -> str:
    """Returns HTML for a coloured metric card."""
    return (
        f"<div class='metric-card' style='--sev-color:{color};'>"
        f"<div class='metric-val'>{value}</div>"
        f"<div class='metric-lbl'>{label}</div>"
        f"</div>"
    )


def _clean_evidence_excerpt(raw: str, max_sentences: int = 3) -> str:
    """
    Extracts up to *max_sentences* sentences from a KB evidence string.

    Strips leading source prefix (e.g. '[A05_injection.md]: '),
    removes markdown heading markers (#), and trims whitespace.
    """
    # strip leading "[source]: " prefix
    if "]: " in raw:
        raw = raw.split("]: ", 1)[1]

    # remove markdown headings
    import re
    raw = re.sub(r"^#+\s*", "", raw, flags=re.MULTILINE)

    # split into sentences and take first max_sentences
    import re as _re
    sentences = _re.split(r"(?<=[.!?])\s+", raw.strip())
    excerpt = " ".join(s.strip() for s in sentences[:max_sentences] if s.strip())
    return excerpt


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
    # raw format: "A08:2025-Software or Data Integrity Failures"
    return raw.replace("-", " ", 1)  # replace only the first dash


def _agent_display(agent: str) -> str:
    """Returns a human-readable agent name."""
    return AGENT_DISPLAY.get(agent, agent.replace("_", " ").title())


# ── warm the retriever at startup ───────────────────────────────────────────
_warm_retriever()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 — HEADER BANNER
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="app-banner">
  <h1>🛡️ AI Code Review &amp; Security Analysis Agent</h1>
  <p>Paste Python or Java code. Two agents check it for quality problems and
     security vulnerabilities, then merge the results.</p>
</div>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 — CODE INPUT
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("<div class='section-title'>Code Input</div>", unsafe_allow_html=True)

col_lang, col_mode = st.columns([1, 3])
with col_lang:
    language_choice: str = st.selectbox(
        "Language",
        ["Python", "Java"],
        help="Auto-detected from uploaded file extension; override if needed.",
    )
lang_key: str = "python" if language_choice == "Python" else "java"

with col_mode:
    input_mode: str = st.radio(
        "Input method",
        ["Upload file", "Paste code"],
        horizontal=True,
        label_visibility="collapsed",
    )

uploaded_code: Optional[str] = None
upload_filename: str = f"submission.{'py' if lang_key == 'python' else 'java'}"

if input_mode == "Upload file":
    uploaded_file = st.file_uploader(
        "Upload a .py or .java file (max 1 MB)",
        type=["py", "java"],
    )
    if uploaded_file is not None:
        if uploaded_file.size > MAX_FILE_SIZE_BYTES:
            st.error(f"❌ File exceeds 1 MB ({uploaded_file.size / 1024 / 1024:.2f} MB).")
        else:
            ext = Path(uploaded_file.name).suffix.lower()
            if ext not in (".py", ".java"):
                st.error(f"❌ Unsupported extension '{ext}'. Only .py and .java are accepted.")
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
        # basic auto-detect from content
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
    disabled=not bool(uploaded_code and uploaded_code.strip()),
)

if analyze_clicked:
    if not uploaded_code or not uploaded_code.strip():
        st.warning("⚠️ Nothing to analyse. Please upload or paste some code first.")
    else:
        # ── syntax validation ────────────────────────────────────────────
        with st.spinner("Validating syntax…"):
            vr = validate_python(uploaded_code) if lang_key == "python" else validate_java(uploaded_code)

        if not vr["is_valid"]:
            st.error("❌ Syntax error — please fix before running analysis.")
            st.error(vr.get("error", "Unknown syntax error."))
        else:
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
            st.session_state["review_report"] = report.model_dump()
            st.session_state["current_code"] = uploaded_code
            st.session_state["lang_key"] = lang_key

            # ── run orchestrator ─────────────────────────────────────────
            with st.spinner("Running parallel agent analysis…"):
                result: AnalysisResult = analyze(
                    uploaded_code, language=lang_key, filename=upload_filename
                )
                report.findings = result.findings
                st.session_state["analysis_result"] = result.model_dump()
                st.session_state["review_report"] = report.model_dump()
                st.session_state["upload_filename"] = upload_filename

            # show agent errors if any
            for agent_name, status in result.run_status.items():
                if status != "SUCCESS":
                    st.warning(f"⚠️ **{_agent_display(agent_name)}**: {status}")

            st.success(f"✅ Analysis complete — {len(result.findings)} finding(s) found.")


# ═══════════════════════════════════════════════════════════════════════════
# SECTIONS 3-5 — RESULTS (only when we have findings in session state)
# ═══════════════════════════════════════════════════════════════════════════
if "analysis_result" not in st.session_state:
    st.stop()

res: Dict[str, Any] = st.session_state["analysis_result"]
findings: List[Dict[str, Any]] = res.get("findings", [])
counts_sev: Dict[str, int] = res.get("counts_by_severity", {})
run_status: Dict[str, str] = res.get("run_status", {})
display_lang: str = st.session_state.get("lang_key", res.get("language", "python"))

# ── section 3: severity summary ─────────────────────────────────────────────
st.markdown("<div class='section-title'>Severity Summary</div>", unsafe_allow_html=True)

total = sum(counts_sev.values())
c_crit = counts_sev.get("CRITICAL", 0)
c_high = counts_sev.get("HIGH", 0)
c_med  = counts_sev.get("MEDIUM", 0)
c_low  = counts_sev.get("LOW", 0)
c_info = counts_sev.get("INFO", 0)

cols = st.columns(6)
cards = [
    ("CRITICAL", c_crit, SEV_COLORS["CRITICAL"]),
    ("HIGH",     c_high, SEV_COLORS["HIGH"]),
    ("MEDIUM",   c_med,  SEV_COLORS["MEDIUM"]),
    ("LOW",      c_low,  SEV_COLORS["LOW"]),
    ("INFO",     c_info, SEV_COLORS["INFO"]),
    ("TOTAL",    total,  "#3B82F6"),
]
for col, (label, val, color) in zip(cols, cards):
    with col:
        st.markdown(_metric_card(label, val, color), unsafe_allow_html=True)

if findings:
    st.markdown("<br>", unsafe_allow_html=True)
    st.bar_chart(
        {k: v for k, v in counts_sev.items() if v > 0},
        color="#3B82F6",
    )
else:
    st.success("🎉 No issues found — code is clean.")

# ── section 4: findings table + filters ─────────────────────────────────────
if findings:
    st.markdown("<div class='section-title'>Findings</div>", unsafe_allow_html=True)

    # ── filters ──────────────────────────────────────────────────────────
    f1, f2 = st.columns(2)
    with f1:
        active_sevs = [s for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                       if counts_sev.get(s, 0) > 0]
        sel_sevs: List[str] = st.multiselect(
            "Filter by severity",
            options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            default=active_sevs,
        )
    with f2:
        all_agents = sorted({f.get("agent", "") for f in findings})
        sel_agents: List[str] = st.multiselect(
            "Filter by agent",
            options=all_agents,
            default=all_agents,
            format_func=_agent_display,
        )

    displayed = [
        f for f in findings
        if _severity_str(f) in sel_sevs and f.get("agent", "") in sel_agents
    ]
    st.caption(f"Showing {len(displayed)} of {len(findings)} findings")

    # ── section 5: expander per finding ──────────────────────────────────
    st.markdown("<div class='section-title'>Finding Details</div>", unsafe_allow_html=True)

    for f in displayed:
        sev         = _severity_str(f)
        title       = f.get("title", "Finding")
        l_start     = f.get("line_start", 1)
        l_end       = f.get("line_end", l_start)
        agent_raw   = f.get("agent", "")
        score       = f.get("severity_score", 0.0)
        confidence  = f.get("confidence", 1.0)
        snippet     = f.get("code_snippet") or ""
        explanation = f.get("explanation") or ""
        suggestion  = f.get("suggestion") or ""
        evidence    = f.get("evidence") or ""
        owasp_raw   = f.get("owasp_category")
        cwe_id      = f.get("cwe_id") or ""
        filename    = f.get("file") or st.session_state.get("upload_filename", "")

        line_label = f"Line {l_start}" if l_start == l_end else f"Lines {l_start}–{l_end}"

        # expander title: badge + title + line
        exp_title = f"[{sev}] {title} — {line_label}"

        with st.expander(exp_title, expanded=False):

            # 1. header
            st.markdown(
                f"{_badge_html(sev)} &nbsp; <span class='finding-header'>{title}</span> &nbsp;"
                f"<span style='color:#64748B;font-size:0.82rem'>{line_label}"
                f"{' · ' + filename if filename else ''}</span>",
                unsafe_allow_html=True,
            )

            # 2. score / confidence / agent
            st.markdown(
                f"<div class='finding-meta'>"
                f"CVSS Score: <strong style='color:#E6EDF7'>{score:.1f}</strong> &nbsp;|&nbsp; "
                f"Confidence: <strong style='color:#E6EDF7'>{confidence:.0%}</strong> &nbsp;|&nbsp; "
                f"Agent: <strong style='color:#E6EDF7'>{_agent_display(agent_raw)}</strong>"
                f"</div>",
                unsafe_allow_html=True,
            )

            # 3. OWASP + CWE
            owasp_text = _owasp_display(owasp_raw)
            if owasp_text or cwe_id:
                parts = []
                if owasp_text:
                    parts.append(f"**OWASP:** {owasp_text}")
                if cwe_id:
                    parts.append(f"**CWE:** {cwe_id}")
                st.markdown("  &nbsp;|&nbsp;  ".join(parts))

            # 4. code snippet
            if snippet.strip():
                st.markdown("**Code snippet:**")
                st.code(snippet, language=display_lang)

            # 5. explanation
            if explanation.strip():
                st.markdown("**Explanation:**")
                st.write(explanation)

            # 6. suggested fix
            if suggestion.strip():
                st.markdown("**Suggested fix:**")
                st.info(suggestion)

            # 7. KB evidence
            if evidence.strip():
                src = _source_from_evidence(evidence)
                excerpt = _clean_evidence_excerpt(evidence)
                st.markdown(f"**Knowledge base — `{src}`:**")
                st.markdown(
                    f"<div class='kb-quote'>{excerpt}</div>",
                    unsafe_allow_html=True,
                )

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6 — FINAL REPORT
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("<div class='section-title'>Final report</div>", unsafe_allow_html=True)

# Build report data covering ALL findings regardless of UI table filters
code_text = st.session_state.get("current_code", "")
loc_calc = len(code_text.splitlines()) if code_text else None
target_file = st.session_state.get("upload_filename", res.get("filename", "unknown"))
target_language = st.session_state.get("lang_key", res.get("language", "python"))

report_data = build_report_data(
    res,
    lines_of_code=loc_calc,
    filename=target_file,
    language=target_language,
)

# 1. Overall risk rating
r_level = report_data["risk_level"]
r_reason = report_data["risk_reason"]
r_color = report_data["risk_color"]
r_badge_cls = "badge-CLEAN" if r_level == "No issues found" else f"badge-{r_level.upper()}"

st.markdown(
    f"<div style='background-color:#07101F; border:1px solid #1E3A5F; border-left:5px solid {r_color}; "
    f"border-radius:8px; padding:1.2rem; margin-bottom:1.4rem;'>"
    f"<div style='display:flex; align-items:center; gap:1.2rem; flex-wrap:wrap;'>"
    f"<span class='badge {r_badge_cls}' style='font-size:0.95rem; padding:6px 16px;'>{r_level.upper()}</span>"
    f"<span style='font-size:1rem; color:#E6EDF7;'>{r_reason}</span>"
    f"</div></div>",
    unsafe_allow_html=True,
)

# 2. File summary
st.markdown("#### 📄 File Summary")
f_meta1, f_meta2, f_meta3, f_meta4 = st.columns(4)
with f_meta1:
    st.metric("Target File", report_data["filename"])
with f_meta2:
    st.metric("Language", report_data["language"].capitalize())
with f_meta3:
    st.metric("Lines of Code", report_data["lines_of_code"])
with f_meta4:
    st.metric("Total Findings", report_data["total_findings"])

counts_map = report_data["counts_by_severity"]
st.caption(
    f"**Severity Breakdown:** "
    f"Critical: `{counts_map.get('CRITICAL', 0)}` | "
    f"High: `{counts_map.get('HIGH', 0)}` | "
    f"Medium: `{counts_map.get('MEDIUM', 0)}` | "
    f"Low: `{counts_map.get('LOW', 0)}` | "
    f"Info: `{counts_map.get('INFO', 0)}`"
)

# 3. Security summary
st.markdown("<br>", unsafe_allow_html=True)
st.markdown("#### 🔒 Security Summary")
sec_data = report_data["security_summary"]
if sec_data:
    sec_rows = "".join(
        f"<tr><td>{cat}</td><td class='num-col'>{cnt}</td></tr>"
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

# 4. Code quality summary
st.markdown("#### 🧹 Code Quality Summary")
qual_data = report_data["quality_summary"]
if qual_data:
    qual_rows = "".join(
        f"<tr><td>{cat}</td><td class='num-col'>{cnt}</td></tr>"
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

# 5. Top 5 issues to fix first
st.markdown("#### ⚠️ Top 5 Issues to Fix First")
top_5_items = report_data["top_5"]
if top_5_items:
    for f in top_5_items:
        t_sev = _severity_str(f)
        t_title = f.get("title", "Finding") if isinstance(f, dict) else getattr(f, "title", "Finding")
        t_start = f.get("line_start", 1) if isinstance(f, dict) else getattr(f, "line_start", 1)
        t_end = f.get("line_end", t_start) if isinstance(f, dict) else getattr(f, "line_end", t_start)
        t_line_str = f"Line {t_start}" if t_start == t_end else f"Lines {t_start}–{t_end}"
        st.markdown(
            f"<div style='margin-bottom:0.45rem; background:#07101F; padding:0.6rem 0.9rem; "
            f"border:1px solid #1E3A5F; border-radius:6px; display:flex; align-items:center; gap:0.75rem;'>"
            f"{_badge_html(t_sev)} <strong style='color:#E6EDF7;'>{t_title}</strong> "
            f"<span style='color:#94A3B8; font-size:0.85rem;'>({t_line_str})</span>"
            f"</div>",
            unsafe_allow_html=True,
        )
else:
    st.info("No issues found to fix.")

# 6. Recommended next steps
st.markdown("#### 💡 Recommended Next Steps")
for step in report_data["recommended_steps"]:
    st.markdown(f"- {step}")

# 7. Two download buttons
st.markdown("<br>", unsafe_allow_html=True)
md_report_text = generate_markdown_report(report_data)
html_report_text = generate_html_report(report_data)
base_name = Path(target_file).stem

col_btn1, col_btn2 = st.columns(2)
with col_btn1:
    st.download_button(
        label="📄 Download report (Markdown)",
        data=md_report_text,
        file_name=f"report_{base_name}.md",
        mime="text/markdown",
        use_container_width=True,
    )
with col_btn2:
    st.download_button(
        label="🌐 Download report (HTML)",
        data=html_report_text,
        file_name=f"report_{base_name}.html",
        mime="text/html",
        use_container_width=True,
    )

