"""
PDF Code Review & Security Analysis Report Generator (Milestone 4, Step 1).

Generates a polished, multi-page PDF report from an AnalysisResult (or serialized dict)
using ReportLab and Matplotlib:
  - Cover page (project title, file name, language, date, Code Health Score & grade)
  - 1. Executive Overview (from PR Summary Agent with safe fallback)
  - 2. Severity Breakdown (metrics table + embedded Matplotlib bar/pie chart)
  - 3. Findings Summary Table (ID, Type, Severity, Line, Category — auto-paginated)
  - 4. Detailed Findings (code snippet, explanation, OWASP/CWE mapping, Remediation fix)
  - 5. Prioritized Remediation Roadmap (Fix Now / Next / Later tiers, Critical/High first)
  - 6. Overall Code Quality Assessment (Strengths, Weaknesses, Health Score Reasoning)

Handles zero findings, very long code lines, special/Unicode characters, 100+ findings
with clean pagination, and missing remediation entries without failing.
"""

from __future__ import annotations

from datetime import datetime, timezone
import io
import textwrap
from typing import Any, Dict, List, Optional, Sequence, Tuple
from xml.sax.saxutils import escape as xml_escape

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ── Constants & Palette ──────────────────────────────────────────────────────

PROJECT_TITLE = "AI Code Review & Security Analysis Report"

SEVERITY_ORDER: List[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_RANK: Dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

# Exact deterministic scoring weights & diminishing-returns caps matching PRSummaryAgent
PENALTY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 15,
    "HIGH": 8,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}

PENALTY_CAPS: Dict[str, int] = {
    "CRITICAL": 45,
    "HIGH": 32,
    "MEDIUM": 20,
    "LOW": 10,
    "INFO": 0,
}

SEV_HEX: Dict[str, str] = {
    "CRITICAL": "#DC2626",
    "HIGH": "#EA580C",
    "MEDIUM": "#CA8A04",
    "LOW": "#2563EB",
    "INFO": "#64748B",
}

EFFORT_RANK: Dict[str, int] = {"Low": 1, "Medium": 2, "High": 3}

NAVY_DARK = colors.HexColor("#0F172A")
NAVY_MID = colors.HexColor("#1E293B")
BLUE_ACCENT = colors.HexColor("#1D4ED8")
BLUE_LIGHT = colors.HexColor("#EFF6FF")
SLATE_TEXT = colors.HexColor("#1E293B")
MUTED_TEXT = colors.HexColor("#475569")
BORDER_GRAY = colors.HexColor("#CBD5E1")
ROW_ALT = colors.HexColor("#F8FAFC")
CODE_BG = colors.HexColor("#F1F5F9")
FIX_BG = colors.HexColor("#ECFDF5")
FIX_BORDER = colors.HexColor("#10B981")
WARN_BG = colors.HexColor("#FFFBEB")
WARN_BORDER = colors.HexColor("#D97706")

# Common Unicode -> ASCII punctuation replacements so built-in PDF WinAnsi fonts stay clean
_UNICODE_REPLACEMENTS: Dict[str, str] = {
    "\u2014": "--",   # em dash
    "\u2013": "-",    # en dash
    "\u2018": "'",    # left single quote
    "\u2019": "'",    # right single quote
    "\u201c": '"',    # left double quote
    "\u201d": '"',    # right double quote
    "\u2026": "...",  # ellipsis
    "\u2022": "*",    # bullet
    "\u2192": "->",   # right arrow
    "\u2190": "<-",   # left arrow
    "\u2264": "<=",   # <=
    "\u2265": ">=",   # >=
    "\u00a0": " ",    # non-breaking space
    "\u2705": "[OK]",
    "\u274c": "[X]",
    "\u26a0": "[!]",
    "\ufe0f": "",
    "\u200b": "",     # zero-width space
}

_OWASP_ENUM_MAP: Dict[str, str] = {
    "A01": "A01:2025-Broken Access Control",
    "A02": "A02:2025-Security Misconfiguration",
    "A03": "A03:2025-Software Supply Chain Failures",
    "A04": "A04:2025-Cryptographic Failures",
    "A05": "A05:2025-Injection",
    "A06": "A06:2025-Insecure Design",
    "A07": "A07:2025-Authentication Failures",
    "A08": "A08:2025-Software or Data Integrity Failures",
    "A09": "A09:2025-Security Logging and Alerting Failures",
    "A10": "A10:2025-Mishandling of Exceptional Conditions",
}


# ── Safe Access & Sanitization Helpers ───────────────────────────────────────

def _get_val(obj: Any, key: str, default: Any = None) -> Any:
    """Uniformly extracts an attribute or dictionary value."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _severity_str(item: Any) -> str:
    """Normalizes a severity enum or string to uppercase canonical form."""
    raw = _get_val(item, "severity", "INFO")
    if hasattr(raw, "value"):
        val = str(raw.value).upper()
    else:
        val = str(raw or "INFO").split(".")[-1].upper()
    return val if val in SEVERITY_RANK else "INFO"


def _owasp_str(finding: Any) -> str:
    """Formats OWASP category and CWE ID cleanly for display."""
    raw = _get_val(finding, "owasp_category", None)
    cwe = str(_get_val(finding, "cwe_id", "") or "").strip()

    owasp_label = ""
    if raw is not None:
        if hasattr(raw, "value"):
            owasp_label = str(raw.value)
        else:
            s = str(raw).strip()
            if s.startswith("OWASPCategory."):
                code = s.split(".", 1)[1]
                owasp_label = _OWASP_ENUM_MAP.get(code, code)
            elif s in _OWASP_ENUM_MAP:
                owasp_label = _OWASP_ENUM_MAP[s]
            elif s and s.lower() != "none":
                owasp_label = s

    if owasp_label and cwe:
        return f"{owasp_label} ({cwe})"
    if owasp_label:
        return owasp_label
    if cwe:
        return cwe
    return "N/A (Code Quality)"


def _sanitize_text(value: Any) -> str:
    """
    Normalizes arbitrary text so ReportLab built-in WinAnsi fonts render cleanly
    without encoding errors or dropped glyphs, while preserving ASCII and Latin-1.
    """
    if value is None:
        return ""
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    for src, dst in _UNICODE_REPLACEMENTS.items():
        if src in text:
            text = text.replace(src, dst)
    # Strip control characters other than newline and tab
    cleaned_chars: List[str] = []
    for ch in text:
        code = ord(ch)
        if ch in ("\n", "\t") or (32 <= code <= 126) or (160 <= code <= 255):
            cleaned_chars.append(ch)
        else:
            # Replace unsupported non-Latin-1 glyphs (e.g. emojis, CJK) safely
            cleaned_chars.append("?")
    return "".join(cleaned_chars)


def _p_escape(value: Any) -> str:
    """Sanitizes and XML-escapes text for safe inclusion in a ReportLab Paragraph."""
    safe = _sanitize_text(value)
    return xml_escape(safe, {'"': "&quot;", "'": "&#39;"})


def _wrap_code_lines(code: str, max_chars: int = 84) -> List[str]:
    """
    Wraps long source code lines (including unbroken tokens) so they never overflow
    a PDF frame horizontally.
    """
    clean = _sanitize_text(code).expandtabs(4)
    if not clean.strip():
        return []
    wrapped: List[str] = []
    for raw_line in clean.split("\n"):
        if len(raw_line) <= max_chars:
            wrapped.append(raw_line)
        else:
            parts = textwrap.wrap(
                raw_line,
                width=max_chars,
                break_long_words=True,
                break_on_hyphens=False,
                drop_whitespace=False,
                replace_whitespace=False,
            )
            if not parts:
                wrapped.append("")
            else:
                for idx, part in enumerate(parts):
                    prefix = "  \\ " if idx > 0 else ""
                    wrapped.append(prefix + part)
    return wrapped


def _code_flowables(
    code: str,
    style: ParagraphStyle,
    max_chars: int = 84,
    lines_per_chunk: int = 28,
) -> List[Paragraph]:
    """
    Converts source code into one or more ReportLab Paragraph flowables.
    Splitting into bounded line chunks guarantees ReportLab never raises a
    LayoutError on very long snippets while keeping proper monospace indentation.
    """
    lines = _wrap_code_lines(code, max_chars=max_chars)
    if not lines:
        return [Paragraph("<i>(No code snippet available)</i>", style)]

    flowables: List[Paragraph] = []
    for start in range(0, len(lines), lines_per_chunk):
        chunk = lines[start:start + lines_per_chunk]
        formatted_lines: List[str] = []
        for ln in chunk:
            escaped = xml_escape(ln, {'"': "&quot;", "'": "&#39;"})
            # Preserve leading indentation and consecutive spaces in Paragraph markup
            escaped = escaped.replace("  ", "&nbsp;&nbsp;")
            if escaped.startswith(" "):
                escaped = "&nbsp;" + escaped[1:]
            formatted_lines.append(escaped if escaped else "&nbsp;")
        markup = "<br/>".join(formatted_lines)
        flowables.append(Paragraph(markup, style))
    return flowables


def _extract_snippet_from_source(source_code: str, line_start: int, line_end: int) -> str:
    """Falls back to slicing source_code when a finding has no embedded code_snippet."""
    if not source_code:
        return ""
    lines = source_code.splitlines()
    if not lines:
        return ""
    start_idx = max(0, int(line_start or 1) - 1)
    end_idx = min(len(lines), max(start_idx + 1, int(line_end or line_start or 1)))
    if start_idx >= len(lines):
        return ""
    return "\n".join(lines[start_idx:end_idx])


def _grade_for_score(score: int) -> str:
    """Maps 0-100 health score to letter grade A-F."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _health_color_hex(score: int) -> str:
    """Maps 0-100 health score to an accessible color hex."""
    if score >= 90:
        return "#059669"
    if score >= 80:
        return "#16A34A"
    if score >= 70:
        return "#CA8A04"
    if score >= 60:
        return "#EA580C"
    return "#DC2626"


def _compute_fallback_health(findings: Sequence[Any]) -> Dict[str, Any]:
    """Deterministically calculates CodeHealthScore fields if absent from result."""
    counts: Dict[str, int] = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        s = _severity_str(f)
        counts[s] = counts.get(s, 0) + 1

    penalties: Dict[str, int] = {}
    total_penalty = 0
    for sev in SEVERITY_ORDER:
        raw_pen = counts[sev] * PENALTY_WEIGHTS[sev]
        capped = min(raw_pen, PENALTY_CAPS[sev])
        penalties[sev] = capped
        total_penalty += capped

    score = max(0, 100 - total_penalty)
    return {
        "score": score,
        "grade": _grade_for_score(score),
        "breakdown_by_severity": counts,
        "penalty_details": penalties,
    }


def _resolve_health_score(result: Any, findings: Sequence[Any]) -> Dict[str, Any]:
    """Extracts health score dict from result or pr_summary, falling back cleanly."""
    hs = _get_val(result, "health_score", None)
    if hs is None:
        pr = _get_val(result, "pr_summary", None)
        hs = _get_val(pr, "health_score", None) if pr is not None else None

    if hs is None:
        return _compute_fallback_health(findings)

    score = int(_get_val(hs, "score", 100))
    grade = str(_get_val(hs, "grade", _grade_for_score(score)) or _grade_for_score(score))
    breakdown = dict(_get_val(hs, "breakdown_by_severity", {}) or {})
    penalties = dict(_get_val(hs, "penalty_details", {}) or {})

    if not breakdown:
        fallback = _compute_fallback_health(findings)
        breakdown = fallback["breakdown_by_severity"]
    if not penalties:
        fallback = _compute_fallback_health(findings)
        penalties = fallback["penalty_details"]

    return {
        "score": score,
        "grade": grade,
        "breakdown_by_severity": breakdown,
        "penalty_details": penalties,
    }


def _sorted_findings(findings: Sequence[Any]) -> List[Any]:
    """Sorts findings by severity tier desc, severity score desc, line start asc."""
    return sorted(
        list(findings),
        key=lambda f: (
            -SEVERITY_RANK.get(_severity_str(f), 0),
            -float(_get_val(f, "severity_score", 0.0) or 0.0),
            int(_get_val(f, "line_start", 1) or 1),
            str(_get_val(f, "id", "") or ""),
        ),
    )


# ── Matplotlib Chart Generation ──────────────────────────────────────────────

def _build_severity_chart_png(counts: Dict[str, int]) -> io.BytesIO:
    """
    Renders a clean high-DPI Matplotlib figure showing severity distribution
    (bar chart + pie chart when findings > 0; clean status bar chart when 0 findings).
    """
    buf = io.BytesIO()
    total = sum(int(counts.get(s, 0)) for s in SEVERITY_ORDER)

    fig = None
    try:
        if total == 0:
            fig, ax = plt.subplots(figsize=(6.4, 2.3), dpi=150)
            ax.barh(["Findings"], [0], color="#10B981", height=0.4)
            ax.set_xlim(0, 1)
            ax.set_xticks([])
            ax.set_yticks([])
            for spine in ax.spines.values():
                spine.set_visible(False)
            ax.set_facecolor("#ECFDF5")
            fig.patch.set_facecolor("#FFFFFF")
            ax.text(
                0.5,
                0.5,
                "Clean Codebase -- 0 Findings Detected (Health Score: 100 / Grade A)",
                ha="center",
                va="center",
                fontsize=10.5,
                fontweight="bold",
                color="#065F46",
                transform=ax.transAxes,
            )
            plt.tight_layout()
            fig.savefig(buf, format="png", bbox_inches="tight")
        else:
            fig, (ax_bar, ax_pie) = plt.subplots(
                1, 2, figsize=(6.8, 2.8), dpi=150, gridspec_kw={"width_ratios": [1.25, 1.0]}
            )
            fig.patch.set_facecolor("#FFFFFF")

            # Left: Bar Chart across all 5 severity levels
            labels = SEVERITY_ORDER
            values = [int(counts.get(s, 0)) for s in labels]
            bar_colors = [SEV_HEX[s] for s in labels]

            bars = ax_bar.bar(labels, values, color=bar_colors, edgecolor="#FFFFFF", linewidth=0.8)
            ax_bar.set_title("Findings by Severity", fontsize=9.5, fontweight="bold", color="#0F172A", pad=8)
            ax_bar.set_ylabel("Count", fontsize=8, color="#475569")
            ax_bar.tick_params(axis="x", labelsize=7.5, colors="#1E293B")
            ax_bar.tick_params(axis="y", labelsize=7.5, colors="#475569")
            ax_bar.set_ylim(0, max(values) * 1.22 + 0.5)
            ax_bar.grid(axis="y", linestyle="--", alpha=0.35, color="#94A3B8")
            ax_bar.set_axisbelow(True)
            ax_bar.spines["top"].set_visible(False)
            ax_bar.spines["right"].set_visible(False)

            for bar, val in zip(bars, values):
                if val > 0:
                    ax_bar.text(
                        bar.get_x() + bar.get_width() / 2.0,
                        val + max(values) * 0.03 + 0.05,
                        str(val),
                        ha="center",
                        va="bottom",
                        fontsize=7.5,
                        fontweight="bold",
                        color="#0F172A",
                    )

            # Right: Donut / Pie Chart for non-zero severities
            nz_labels = [s for s in labels if counts.get(s, 0) > 0]
            nz_values = [int(counts[s]) for s in nz_labels]
            nz_colors = [SEV_HEX[s] for s in nz_labels]

            wedges, texts, autotexts = ax_pie.pie(
                nz_values,
                labels=nz_labels,
                colors=nz_colors,
                autopct="%1.0f%%",
                startangle=140,
                pctdistance=0.75,
                wedgeprops={"width": 0.45, "edgecolor": "#FFFFFF", "linewidth": 1.2},
                textprops={"fontsize": 7.2, "color": "#1E293B"},
            )
            for at in autotexts:
                at.set_fontsize(7.0)
                at.set_fontweight("bold")
                at.set_color("#0F172A")
            ax_pie.set_title("Severity Share", fontsize=9.5, fontweight="bold", color="#0F172A", pad=8)

            plt.tight_layout(pad=1.2)
            fig.savefig(buf, format="png", bbox_inches="tight")
    finally:
        if fig is not None:
            plt.close(fig)

    buf.seek(0)
    return buf


# ── Stylesheet & Page Chrome ─────────────────────────────────────────────────

def _build_styles() -> Dict[str, ParagraphStyle]:
    """Creates reusable ReportLab ParagraphStyles for the PDF report."""
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "CoverTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=28,
            textColor=colors.white,
            alignment=TA_LEFT,
            spaceAfter=6,
        ),
        "cover_sub": ParagraphStyle(
            "CoverSub",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10.5,
            leading=15,
            textColor=colors.HexColor("#BFDBFE"),
            alignment=TA_LEFT,
        ),
        "h1": ParagraphStyle(
            "SectionH1",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=NAVY_DARK,
            spaceBefore=12,
            spaceAfter=6,
            borderWidth=0,
        ),
        "h2": ParagraphStyle(
            "SectionH2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=14,
            textColor=BLUE_ACCENT,
            spaceBefore=8,
            spaceAfter=4,
        ),
        "finding_title": ParagraphStyle(
            "FindingTitle",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=NAVY_DARK,
            spaceBefore=8,
            spaceAfter=2,
        ),
        "body": ParagraphStyle(
            "BodyTextCustom",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=SLATE_TEXT,
            spaceAfter=4,
            wordWrap="CJK",
        ),
        "muted": ParagraphStyle(
            "MutedMeta",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=MUTED_TEXT,
            spaceAfter=4,
            wordWrap="CJK",
        ),
        "bullet": ParagraphStyle(
            "BulletCustom",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            leftIndent=14,
            bulletIndent=4,
            textColor=SLATE_TEXT,
            spaceAfter=3,
            wordWrap="CJK",
        ),
        "table_hdr": ParagraphStyle(
            "TableHeader",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.white,
            alignment=TA_LEFT,
        ),
        "table_cell": ParagraphStyle(
            "TableCell",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=10.5,
            textColor=SLATE_TEXT,
            wordWrap="CJK",
        ),
        "table_cell_center": ParagraphStyle(
            "TableCellCenter",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10.5,
            textColor=SLATE_TEXT,
            alignment=TA_CENTER,
        ),
        "code": ParagraphStyle(
            "CodeBlock",
            parent=base["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=NAVY_DARK,
            backColor=CODE_BG,
            borderColor=BORDER_GRAY,
            borderWidth=0.5,
            borderPadding=5,
            leftIndent=2,
            rightIndent=2,
            spaceBefore=2,
            spaceAfter=5,
        ),
        "fix_code": ParagraphStyle(
            "FixCodeBlock",
            parent=base["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#064E3B"),
            backColor=FIX_BG,
            borderColor=FIX_BORDER,
            borderWidth=0.6,
            borderPadding=5,
            leftIndent=2,
            rightIndent=2,
            spaceBefore=2,
            spaceAfter=5,
        ),
        "callout": ParagraphStyle(
            "CalloutBox",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=SLATE_TEXT,
            backColor=BLUE_LIGHT,
            borderColor=BLUE_ACCENT,
            borderWidth=0.6,
            borderPadding=7,
            spaceBefore=4,
            spaceAfter=6,
            wordWrap="CJK",
        ),
    }


def _make_page_chrome(filename: str, generated_date: str):
    """Returns header/footer draw callbacks for ReportLab SimpleDocTemplate."""
    safe_file = _sanitize_text(filename)
    if len(safe_file) > 50:
        safe_file = safe_file[:47] + "..."

    def _on_first_page(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED_TEXT)
        canvas.drawString(
            doc.leftMargin,
            0.45 * inch,
            f"File: {safe_file} | Generated {generated_date}",
        )
        canvas.drawRightString(
            letter[0] - doc.rightMargin,
            0.45 * inch,
            f"Page {doc.page}",
        )
        canvas.restoreState()

    def _on_later_pages(canvas, doc):
        canvas.saveState()
        page_w, page_h = letter
        # Top subtle header rule
        canvas.setStrokeColor(BORDER_GRAY)
        canvas.setLineWidth(0.5)
        canvas.line(doc.leftMargin, page_h - 0.55 * inch, page_w - doc.rightMargin, page_h - 0.55 * inch)
        canvas.setFont("Helvetica-Bold", 7.5)
        canvas.setFillColor(NAVY_MID)
        canvas.drawString(doc.leftMargin, page_h - 0.48 * inch, PROJECT_TITLE)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED_TEXT)
        canvas.drawRightString(page_w - doc.rightMargin, page_h - 0.48 * inch, f"File: {safe_file}")

        # Bottom footer rule with file name and page number
        canvas.line(doc.leftMargin, 0.58 * inch, page_w - doc.rightMargin, 0.58 * inch)
        canvas.drawString(doc.leftMargin, 0.43 * inch, f"File: {safe_file} | Generated {generated_date}")
        canvas.drawRightString(page_w - doc.rightMargin, 0.43 * inch, f"Page {doc.page}")
        canvas.restoreState()

    return _on_first_page, _on_later_pages


# ── Section Builders ─────────────────────────────────────────────────────────

def _build_cover_page(
    story: List[Any],
    styles: Dict[str, ParagraphStyle],
    filename: str,
    language: str,
    generated_date: str,
    source_code: str,
    findings: Sequence[Any],
    remediations: Sequence[Any],
    health: Dict[str, Any],
) -> None:
    """Builds the Cover Page with project title, metadata, and Code Health Score."""
    # Deep Navy Banner Table
    banner_data = [
        [Paragraph(_p_escape(PROJECT_TITLE), styles["cover_title"])],
        [
            Paragraph(
                "Automated Multi-Agent Code Quality, OWASP Security, Remediation &amp; PR Readiness Audit",
                styles["cover_sub"],
            )
        ],
    ]
    banner = Table(banner_data, colWidths=[6.9 * inch])
    banner.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), NAVY_DARK),
                ("TOPPADDING", (0, 0), (-1, 0), 22),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 20),
                ("LEFTPADDING", (0, 0), (-1, -1), 18),
                ("RIGHTPADDING", (0, 0), (-1, -1), 18),
                ("LINEBELOW", (0, -1), (-1, -1), 3, BLUE_ACCENT),
            ]
        )
    )
    story.append(Spacer(1, 0.4 * inch))
    story.append(banner)
    story.append(Spacer(1, 0.4 * inch))

    # Code Health Score Highlight Card
    score = int(health["score"])
    grade = str(health["grade"])
    score_hex = _health_color_hex(score)
    score_color = colors.HexColor(score_hex)

    score_style = ParagraphStyle(
        "CoverScore",
        fontName="Helvetica-Bold",
        fontSize=30,
        leading=34,
        textColor=score_color,
        alignment=TA_CENTER,
    )
    grade_style = ParagraphStyle(
        "CoverGrade",
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=NAVY_DARK,
        alignment=TA_CENTER,
    )
    health_card = Table(
        [
            [Paragraph("CODE HEALTH SCORE", styles["table_cell_center"])],
            [Paragraph(f"{score} / 100", score_style)],
            [Paragraph(f"Grade: { _p_escape(grade) }", grade_style)],
        ],
        colWidths=[6.9 * inch],
    )
    health_card.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), ROW_ALT),
                ("BOX", (0, 0), (-1, -1), 1.5, score_color),
                ("TOPPADDING", (0, 0), (-1, 0), 12),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 14),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ]
        )
    )
    story.append(health_card)
    story.append(Spacer(1, 0.35 * inch))

    # Target Metadata Table
    loc = len(source_code.splitlines()) if source_code else 0
    verified_cnt = sum(1 for r in remediations if bool(_get_val(r, "verified", False)))
    rem_total = len(remediations)
    rem_summary = (
        f"{verified_cnt} of {rem_total} automated fixes verified"
        if rem_total > 0
        else ("No fixes needed (clean file)" if not findings else "No automated remediations generated")
    )

    meta_rows = [
        [Paragraph("<b>Report Field</b>", styles["table_hdr"]), Paragraph("<b>Details</b>", styles["table_hdr"])],
        [Paragraph("<b>File Name</b>", styles["table_cell"]), Paragraph(_p_escape(filename), styles["table_cell"])],
        [Paragraph("<b>Language</b>", styles["table_cell"]), Paragraph(_p_escape(language.capitalize()), styles["table_cell"])],
        [Paragraph("<b>Report Date</b>", styles["table_cell"]), Paragraph(_p_escape(generated_date), styles["table_cell"])],
        [Paragraph("<b>Lines of Code</b>", styles["table_cell"]), Paragraph(str(loc), styles["table_cell"])],
        [Paragraph("<b>Total Findings</b>", styles["table_cell"]), Paragraph(str(len(findings)), styles["table_cell"])],
        [Paragraph("<b>Code Health Score</b>", styles["table_cell"]), Paragraph(f"{score} / 100 (Grade {_p_escape(grade)})", styles["table_cell"])],
        [Paragraph("<b>Remediation Status</b>", styles["table_cell"]), Paragraph(_p_escape(rem_summary), styles["table_cell"])],
    ]
    meta_tbl = Table(meta_rows, colWidths=[2.1 * inch, 4.8 * inch])
    meta_tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY_MID),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ROW_ALT]),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER_GRAY),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(meta_tbl)
    story.append(PageBreak())


def _build_executive_overview(
    story: List[Any],
    styles: Dict[str, ParagraphStyle],
    result: Any,
    findings: Sequence[Any],
    health: Dict[str, Any],
    filename: str,
) -> None:
    """Section 1: Executive Overview pulled from PR Summary Agent with safe fallback."""
    story.append(Paragraph("1. Executive Overview", styles["h1"]))

    pr_summary = _get_val(result, "pr_summary", None)
    overview = str(_get_val(pr_summary, "executive_overview", "") or "").strip()
    top_risks = list(_get_val(pr_summary, "top_risks", []) or [])

    if not overview:
        if not findings:
            overview = (
                f"Static code quality and OWASP security review of '{filename}' completed with "
                f"zero detected findings. The file achieved a Code Health Score of "
                f"{health['score']}/100 (Grade {health['grade']}) and is ready for review/merge."
            )
        else:
            counts = health["breakdown_by_severity"]
            overview = (
                f"Automated multi-agent review of '{filename}' identified {len(findings)} finding(s) "
                f"(Critical: {counts.get('CRITICAL', 0)}, High: {counts.get('HIGH', 0)}, "
                f"Medium: {counts.get('MEDIUM', 0)}, Low: {counts.get('LOW', 0)}, "
                f"Info: {counts.get('INFO', 0)}), resulting in a Code Health Score of "
                f"{health['score']}/100 (Grade {health['grade']})."
            )

    story.append(Paragraph(_p_escape(overview), styles["callout"]))

    if top_risks:
        story.append(Paragraph("Key Highlighted Risks", styles["h2"]))
        for risk in top_risks[:8]:
            story.append(Paragraph(_p_escape(risk), styles["bullet"], bulletText="*"))
    elif not findings:
        story.append(
            Paragraph(
                "No high-priority security or maintainability risks were detected in this submission.",
                styles["body"],
            )
        )
    story.append(Spacer(1, 0.1 * inch))


def _build_severity_breakdown(
    story: List[Any],
    styles: Dict[str, ParagraphStyle],
    findings: Sequence[Any],
    health: Dict[str, Any],
) -> None:
    """Section 2: Severity Breakdown table + embedded Matplotlib bar/pie chart."""
    story.append(Paragraph("2. Severity Breakdown", styles["h1"]))

    counts: Dict[str, int] = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        s = _severity_str(f)
        counts[s] = counts.get(s, 0) + 1

    total = sum(counts.values())
    penalties: Dict[str, int] = health.get("penalty_details", {}) or {}

    rows: List[List[Any]] = [
        [
            Paragraph("<b>Severity</b>", styles["table_hdr"]),
            Paragraph("<b>Count</b>", styles["table_hdr"]),
            Paragraph("<b>Share (%)</b>", styles["table_hdr"]),
            Paragraph("<b>Weight / Cap</b>", styles["table_hdr"]),
            Paragraph("<b>Penalty Applied</b>", styles["table_hdr"]),
        ]
    ]
    for sev in SEVERITY_ORDER:
        cnt = counts[sev]
        pct = f"{(cnt / total * 100.0):.1f}%" if total > 0 else "0.0%"
        pen = int(penalties.get(sev, min(cnt * PENALTY_WEIGHTS[sev], PENALTY_CAPS[sev])))
        sev_label = f"<font color='{SEV_HEX[sev]}'><b>{sev}</b></font>"
        rows.append(
            [
                Paragraph(sev_label, styles["table_cell"]),
                Paragraph(str(cnt), styles["table_cell_center"]),
                Paragraph(pct, styles["table_cell_center"]),
                Paragraph(f"-{PENALTY_WEIGHTS[sev]} pts (cap {PENALTY_CAPS[sev]})", styles["table_cell_center"]),
                Paragraph(f"-{pen} pts", styles["table_cell_center"]),
            ]
        )

    total_pen = sum(int(penalties.get(s, 0)) for s in SEVERITY_ORDER)
    rows.append(
        [
            Paragraph("<b>TOTAL</b>", styles["table_cell"]),
            Paragraph(f"<b>{total}</b>", styles["table_cell_center"]),
            Paragraph("<b>100.0%</b>" if total > 0 else "<b>0.0%</b>", styles["table_cell_center"]),
            Paragraph("<b>Base 100 pts</b>", styles["table_cell_center"]),
            Paragraph(f"<b>-{total_pen} pts (Score: {health['score']})</b>", styles["table_cell_center"]),
        ]
    )

    tbl = Table(rows, colWidths=[1.25 * inch, 0.85 * inch, 1.0 * inch, 1.75 * inch, 2.05 * inch])
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY_MID),
                ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, ROW_ALT]),
                ("BACKGROUND", (0, -1), (-1, -1), BLUE_LIGHT),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER_GRAY),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(tbl)
    story.append(Spacer(1, 0.14 * inch))

    # Matplotlib Chart
    chart_buf = _build_severity_chart_png(counts)
    chart_height = 2.1 * inch if total == 0 else 2.65 * inch
    chart_img = Image(chart_buf, width=6.7 * inch, height=chart_height)
    chart_img.hAlign = "CENTER"
    story.append(chart_img)
    story.append(Spacer(1, 0.12 * inch))


def _build_findings_summary_table(
    story: List[Any],
    styles: Dict[str, ParagraphStyle],
    sorted_findings: Sequence[Any],
) -> None:
    """Section 3: Findings Summary Table (ID, Type, Severity, Line, Category)."""
    story.append(Paragraph("3. Findings Summary Table", styles["h1"]))

    if not sorted_findings:
        story.append(
            Paragraph(
                "No security vulnerabilities or code quality issues were detected. Summary table is empty.",
                styles["callout"],
            )
        )
        return

    rows: List[List[Any]] = [
        [
            Paragraph("<b>ID</b>", styles["table_hdr"]),
            Paragraph("<b>Type</b>", styles["table_hdr"]),
            Paragraph("<b>Severity</b>", styles["table_hdr"]),
            Paragraph("<b>Line</b>", styles["table_hdr"]),
            Paragraph("<b>Category</b>", styles["table_hdr"]),
        ]
    ]

    for idx, f in enumerate(sorted_findings, start=1):
        fid = str(_get_val(f, "id", f"F-{idx:03d}") or f"F-{idx:03d}")
        title = str(_get_val(f, "title", "Unnamed Finding") or "Unnamed Finding")
        sev = _severity_str(f)
        l_start = int(_get_val(f, "line_start", 1) or 1)
        l_end = int(_get_val(f, "line_end", l_start) or l_start)
        line_str = str(l_start) if l_start == l_end else f"{l_start}-{l_end}"
        category = str(_get_val(f, "category", "General") or "General")

        rows.append(
            [
                Paragraph(_p_escape(fid), styles["table_cell"]),
                Paragraph(_p_escape(title), styles["table_cell"]),
                Paragraph(f"<font color='{SEV_HEX[sev]}'><b>{sev}</b></font>", styles["table_cell_center"]),
                Paragraph(_p_escape(line_str), styles["table_cell_center"]),
                Paragraph(_p_escape(category), styles["table_cell"]),
            ]
        )

    tbl = Table(
        rows,
        colWidths=[0.95 * inch, 2.55 * inch, 0.9 * inch, 0.75 * inch, 1.75 * inch],
        repeatRows=1,
    )
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY_MID),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ROW_ALT]),
                ("GRID", (0, 0), (-1, -1), 0.45, BORDER_GRAY),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(tbl)
    story.append(Spacer(1, 0.14 * inch))


def _build_detailed_findings(
    story: List[Any],
    styles: Dict[str, ParagraphStyle],
    sorted_findings: Sequence[Any],
    remediations: Sequence[Any],
    source_code: str,
) -> None:
    """
    Section 4: Detailed Findings — each with code snippet, explanation, OWASP mapping,
    and Remediation Agent fix (or graceful fallback when remediation is missing).
    """
    story.append(Paragraph("4. Detailed Findings", styles["h1"]))

    if not sorted_findings:
        story.append(
            Paragraph(
                "Zero findings detected -- no individual vulnerability or quality smell details to report.",
                styles["body"],
            )
        )
        return

    rem_by_id: Dict[str, Any] = {}
    for rem in remediations:
        rid = str(_get_val(rem, "finding_id", "") or "").strip()
        if rid:
            rem_by_id[rid] = rem

    for idx, f in enumerate(sorted_findings, start=1):
        fid = str(_get_val(f, "id", f"F-{idx:03d}") or f"F-{idx:03d}")
        title = str(_get_val(f, "title", "Finding") or "Finding")
        sev = _severity_str(f)
        agent = str(_get_val(f, "agent", "unknown") or "unknown")
        category = str(_get_val(f, "category", "General") or "General")
        l_start = int(_get_val(f, "line_start", 1) or 1)
        l_end = int(_get_val(f, "line_end", l_start) or l_start)
        line_str = f"Line {l_start}" if l_start == l_end else f"Lines {l_start}-{l_end}"
        sev_score = float(_get_val(f, "severity_score", 0.0) or 0.0)
        confidence = float(_get_val(f, "confidence", 1.0) or 0.0)
        explanation = str(_get_val(f, "explanation", "") or "").strip()
        suggestion = str(_get_val(f, "suggestion", "") or "").strip()
        snippet = str(_get_val(f, "code_snippet", "") or "").strip()
        if not snippet:
            snippet = _extract_snippet_from_source(source_code, l_start, l_end)

        owasp_mapping = _owasp_str(f)

        # Keep only the small header + metadata strip together so huge findings paginate smoothly
        hdr_html = (
            f"<font color='{SEV_HEX[sev]}'>[{sev}]</font> "
            f"{_p_escape(fid)}: {_p_escape(title)} ({_p_escape(line_str)})"
        )
        meta_html = (
            f"<b>Agent:</b> {_p_escape(agent)} &nbsp;|&nbsp; "
            f"<b>Category:</b> {_p_escape(category)} &nbsp;|&nbsp; "
            f"<b>Score:</b> {sev_score:.1f}/10 &nbsp;|&nbsp; "
            f"<b>Confidence:</b> {confidence:.0%}<br/>"
            f"<b>OWASP Mapping:</b> {_p_escape(owasp_mapping)}"
        )
        story.append(
            KeepTogether(
                [
                    Paragraph(hdr_html, styles["finding_title"]),
                    Paragraph(meta_html, styles["muted"]),
                ]
            )
        )

        # Explanation
        story.append(
            Paragraph(
                f"<b>Explanation:</b> {_p_escape(explanation or 'No explanation provided.')}",
                styles["body"],
            )
        )

        # Vulnerable / Flagged Code Snippet
        if snippet:
            story.append(Paragraph("<b>Code Snippet (Original):</b>", styles["muted"]))
            story.extend(_code_flowables(snippet, styles["code"]))

        # Remediation Agent Fix
        rem = rem_by_id.get(fid)
        if rem is not None:
            verified = bool(_get_val(rem, "verified", False))
            ver_tag = (
                "<font color='#059669'><b>[VERIFIED FIX]</b></font>"
                if verified
                else "<font color='#D97706'><b>[MANUAL REVIEW]</b></font>"
            )
            ver_note = str(_get_val(rem, "verification_note", "") or "").strip()
            fix_summary = str(_get_val(rem, "fix_summary", "") or "").strip()
            corrected = str(_get_val(rem, "corrected_code", "") or "").strip()
            best_practice = str(_get_val(rem, "best_practice", "") or "").strip()
            refs = list(_get_val(rem, "references", []) or [])

            story.append(
                Paragraph(
                    f"<b>Remediation Agent Fix:</b> {ver_tag} "
                    f"{_p_escape(fix_summary or 'See recommended fix below.')}",
                    styles["body"],
                )
            )
            if ver_note:
                story.append(Paragraph(f"<b>Verification Note:</b> {_p_escape(ver_note)}", styles["muted"]))
            if corrected:
                story.append(Paragraph("<b>Corrected Code:</b>", styles["muted"]))
                story.extend(_code_flowables(corrected, styles["fix_code"]))
            if best_practice:
                story.append(Paragraph(f"<b>Best Practice:</b> {_p_escape(best_practice)}", styles["body"]))
            if refs:
                ref_text = ", ".join(_sanitize_text(r) for r in refs)
                story.append(Paragraph(f"<b>KB References:</b> {_p_escape(ref_text)}", styles["muted"]))
        else:
            fallback_msg = (
                f"No automated remediation generated for this finding. Guidance: {suggestion}"
                if suggestion
                else "No automated remediation generated for this finding; manual code review recommended."
            )
            story.append(Paragraph(f"<b>Remediation Agent Fix:</b> {_p_escape(fallback_msg)}", styles["body"]))

        # Thin separator line between findings
        sep = Table([[""]], colWidths=[6.9 * inch], rowHeights=[1])
        sep.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, BORDER_GRAY)]))
        story.append(Spacer(1, 0.04 * inch))
        story.append(sep)
        story.append(Spacer(1, 0.06 * inch))


def _build_remediation_roadmap(
    story: List[Any],
    styles: Dict[str, ParagraphStyle],
    result: Any,
    sorted_findings: Sequence[Any],
) -> None:
    """
    Section 5: Prioritized Remediation Roadmap — Critical/High first,
    grouped into Fix Now / Next / Later tiers.
    """
    story.append(Paragraph("5. Prioritized Remediation Roadmap", styles["h1"]))

    if not sorted_findings:
        story.append(
            Paragraph(
                "No remediation tasks required -- all quality and security checks passed with zero findings.",
                styles["callout"],
            )
        )
        return

    pr_summary = _get_val(result, "pr_summary", None)
    pr_fixes = list(_get_val(pr_summary, "prioritized_fixes", []) or []) if pr_summary is not None else []

    # Build unified roadmap entries sorted by severity desc, effort asc
    entries: List[Dict[str, str]] = []
    if pr_fixes:
        for pf in pr_fixes:
            sev = _severity_str(pf)
            effort = str(_get_val(pf, "effort", "Medium") or "Medium")
            entries.append(
                {
                    "finding_id": str(_get_val(pf, "finding_id", "") or ""),
                    "title": str(_get_val(pf, "title", "Finding") or "Finding"),
                    "severity": sev,
                    "effort": effort,
                    "reason": str(_get_val(pf, "reason", "") or ""),
                }
            )
    else:
        for idx, f in enumerate(sorted_findings, start=1):
            sev = _severity_str(f)
            effort = "Medium" if sev in ("CRITICAL", "HIGH") else "Low"
            entries.append(
                {
                    "finding_id": str(_get_val(f, "id", f"F-{idx:03d}") or f"F-{idx:03d}"),
                    "title": str(_get_val(f, "title", "Finding") or "Finding"),
                    "severity": sev,
                    "effort": effort,
                    "reason": str(_get_val(f, "suggestion", "") or _get_val(f, "explanation", "") or "")[:140],
                }
            )

    entries.sort(
        key=lambda e: (
            -SEVERITY_RANK.get(e["severity"], 0),
            EFFORT_RANK.get(e["effort"], 2),
            e["finding_id"],
        )
    )

    tiers: List[Tuple[str, str, List[Dict[str, str]]]] = [
        (
            "Fix Now (Immediate -- Critical & High)",
            "#DC2626",
            [e for e in entries if e["severity"] in ("CRITICAL", "HIGH")],
        ),
        (
            "Next (Short-Term -- Medium)",
            "#CA8A04",
            [e for e in entries if e["severity"] == "MEDIUM"],
        ),
        (
            "Later (Backlog -- Low & Info)",
            "#2563EB",
            [e for e in entries if e["severity"] in ("LOW", "INFO")],
        ),
    ]

    for tier_title, accent_hex, items in tiers:
        story.append(
            Paragraph(
                f"<font color='{accent_hex}'><b>{_p_escape(tier_title)}</b></font> "
                f"({len(items)} item{'s' if len(items) != 1 else ''})",
                styles["h2"],
            )
        )
        if not items:
            story.append(Paragraph("No findings assigned to this priority tier.", styles["muted"]))
            continue

        rows: List[List[Any]] = [
            [
                Paragraph("<b>ID</b>", styles["table_hdr"]),
                Paragraph("<b>Title</b>", styles["table_hdr"]),
                Paragraph("<b>Severity</b>", styles["table_hdr"]),
                Paragraph("<b>Effort</b>", styles["table_hdr"]),
                Paragraph("<b>Rationale</b>", styles["table_hdr"]),
            ]
        ]
        for item in items:
            sev = item["severity"]
            rows.append(
                [
                    Paragraph(_p_escape(item["finding_id"]), styles["table_cell"]),
                    Paragraph(_p_escape(item["title"]), styles["table_cell"]),
                    Paragraph(f"<font color='{SEV_HEX[sev]}'><b>{sev}</b></font>", styles["table_cell_center"]),
                    Paragraph(_p_escape(item["effort"]), styles["table_cell_center"]),
                    Paragraph(_p_escape(item["reason"] or "Address according to severity tier."), styles["table_cell"]),
                ]
            )

        tbl = Table(
            rows,
            colWidths=[0.85 * inch, 1.9 * inch, 0.85 * inch, 0.7 * inch, 2.6 * inch],
            repeatRows=1,
        )
        tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), NAVY_MID),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ROW_ALT]),
                    ("GRID", (0, 0), (-1, -1), 0.45, BORDER_GRAY),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(tbl)
        story.append(Spacer(1, 0.1 * inch))


def _build_quality_assessment(
    story: List[Any],
    styles: Dict[str, ParagraphStyle],
    sorted_findings: Sequence[Any],
    remediations: Sequence[Any],
    health: Dict[str, Any],
    language: str,
) -> None:
    """
    Section 6: Overall Code Quality Assessment — Strengths, Weaknesses,
    and transparent Health Score Reasoning.
    """
    story.append(Paragraph("6. Overall Code Quality Assessment", styles["h1"]))

    counts: Dict[str, int] = {sev: 0 for sev in SEVERITY_ORDER}
    sec_count = 0
    qual_count = 0
    categories: Dict[str, int] = {}
    for f in sorted_findings:
        sev = _severity_str(f)
        counts[sev] = counts.get(sev, 0) + 1
        agent = str(_get_val(f, "agent", "") or "").lower()
        if "security" in agent or _get_val(f, "owasp_category", None) is not None:
            sec_count += 1
        else:
            qual_count += 1
        cat = str(_get_val(f, "category", "General") or "General")
        categories[cat] = categories.get(cat, 0) + 1

    verified_cnt = sum(1 for r in remediations if bool(_get_val(r, "verified", False)))
    unverified_cnt = max(0, len(remediations) - verified_cnt)

    # Strengths
    strengths: List[str] = []
    if not sorted_findings:
        strengths.append(f"Clean {language.capitalize()} code with zero detected security or quality defects.")
        strengths.append("No OWASP Top 10 vulnerability patterns or maintainability smells were triggered.")
    else:
        if counts["CRITICAL"] == 0:
            strengths.append("Zero Critical-severity security vulnerabilities detected.")
        if counts["CRITICAL"] == 0 and counts["HIGH"] == 0:
            strengths.append("No High or Critical release-blocking issues detected.")
        if qual_count == 0:
            strengths.append("Code structure passed all automated code quality and complexity checks cleanly.")
        if sec_count == 0:
            strengths.append("Passed all automated OWASP Top 10:2025 static security rules with zero alerts.")
        if verified_cnt > 0:
            strengths.append(
                f"{verified_cnt} of {len(remediations)} automated fix(es) passed two-tier AST syntax and detector re-scan verification."
            )
        if not strengths:
            strengths.append("All findings were cleanly localized to exact line spans with actionable remediation guidance.")

    # Weaknesses
    weaknesses: List[str] = []
    if not sorted_findings:
        weaknesses.append("No static defects detected; continue pairing automated analysis with integration and runtime testing.")
    else:
        if counts["CRITICAL"] > 0:
            weaknesses.append(
                f"{counts['CRITICAL']} Critical finding(s) present immediate exploitation or reliability risk and block release."
            )
        if counts["HIGH"] > 0:
            weaknesses.append(
                f"{counts['HIGH']} High-severity issue(s) require remediation prior to production deployment."
            )
        if sec_count > 0 and qual_count > 0:
            weaknesses.append(
                f"Both security ({sec_count}) and maintainability ({qual_count}) concerns were flagged across the file."
            )
        elif sec_count > 0:
            weaknesses.append(f"Security posture is the primary weakness ({sec_count} security finding(s) flagged).")
        elif qual_count > 0:
            weaknesses.append(f"Maintainability debt detected ({qual_count} code quality smell(s) flagged).")

        if unverified_cnt > 0:
            weaknesses.append(
                f"{unverified_cnt} finding(s) require manual developer verification because automated patches could not be fully verified."
            )
        if categories:
            top_cat, top_cat_cnt = max(categories.items(), key=lambda kv: kv[1])
            weaknesses.append(f"Highest defect concentration is in category '{top_cat}' ({top_cat_cnt} finding(s)).")

    story.append(Paragraph("Strengths", styles["h2"]))
    for s in strengths:
        story.append(Paragraph(_p_escape(s), styles["bullet"], bulletText="*"))

    story.append(Paragraph("Weaknesses", styles["h2"]))
    for w in weaknesses:
        story.append(Paragraph(_p_escape(w), styles["bullet"], bulletText="*"))

    # Health Score Reasoning
    story.append(Paragraph("Health Score Reasoning", styles["h2"]))
    penalties = health.get("penalty_details", {}) or {}
    total_penalty = sum(int(penalties.get(sev, 0)) for sev in SEVERITY_ORDER)
    parts = [
        f"{sev}: -{int(penalties.get(sev, 0))} pts"
        for sev in SEVERITY_ORDER
        if int(penalties.get(sev, 0)) > 0
    ]
    penalty_breakdown = ", ".join(parts) if parts else "No penalties deducted"
    reasoning = (
        f"The deterministic Code Health Score starts at 100 points and deducts capped severity penalties "
        f"(Critical: -15/finding cap 45; High: -8/finding cap 32; Medium: -4/finding cap 20; "
        f"Low: -1/finding cap 10; Info: 0). For this submission, total penalties equal -{total_penalty} points "
        f"({penalty_breakdown}), yielding a final score of {health['score']}/100 (Grade {health['grade']}). "
        f"Grade thresholds: A (90-100), B (80-89), C (70-79), D (60-69), F (<60)."
    )
    story.append(Paragraph(_p_escape(reasoning), styles["callout"]))


# ── Public Entrypoint ────────────────────────────────────────────────────────

def generate_report(
    result: Any,
    source_code: str = "",
    filename: Optional[str] = None,
    language: Optional[str] = None,
) -> bytes:
    """
    Generates a complete, paginated PDF code review and security analysis report.

    Args:
        result: AnalysisResult Pydantic model or serialized dictionary from orchestrator.analyze().
        source_code: Full source code string that was analyzed.
        filename: Optional target file name (defaults to result.filename or 'unknown').
        language: Optional target programming language (defaults to result.language or 'python').

    Returns:
        Raw PDF document bytes starting with b'%PDF-'.
    """
    resolved_filename = (
        str(filename).strip()
        if filename is not None and str(filename).strip()
        else str(_get_val(result, "filename", "unknown") or "unknown")
    )
    resolved_language = (
        str(language).strip()
        if language is not None and str(language).strip()
        else str(_get_val(result, "language", "python") or "python")
    )
    raw_findings = list(_get_val(result, "findings", []) or [])
    remediations = list(_get_val(result, "remediations", []) or [])
    sorted_findings = _sorted_findings(raw_findings)
    health = _resolve_health_score(result, sorted_findings)
    generated_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    styles = _build_styles()
    pdf_buf = io.BytesIO()
    doc = SimpleDocTemplate(
        pdf_buf,
        pagesize=letter,
        leftMargin=0.8 * inch,
        rightMargin=0.8 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title=_sanitize_text(f"{PROJECT_TITLE} - {resolved_filename}"),
        author="AI Code Review & Security Analysis Agent",
    )

    story: List[Any] = []

    # Cover Page
    _build_cover_page(
        story=story,
        styles=styles,
        filename=resolved_filename,
        language=resolved_language,
        generated_date=generated_date,
        source_code=source_code or "",
        findings=sorted_findings,
        remediations=remediations,
        health=health,
    )

    # 1. Executive Overview
    _build_executive_overview(
        story=story,
        styles=styles,
        result=result,
        findings=sorted_findings,
        health=health,
        filename=resolved_filename,
    )

    # 2. Severity Breakdown (Table + Matplotlib Chart)
    _build_severity_breakdown(
        story=story,
        styles=styles,
        findings=sorted_findings,
        health=health,
    )

    # 3. Findings Summary Table
    _build_findings_summary_table(
        story=story,
        styles=styles,
        sorted_findings=sorted_findings,
    )

    # 4. Detailed Findings
    _build_detailed_findings(
        story=story,
        styles=styles,
        sorted_findings=sorted_findings,
        remediations=remediations,
        source_code=source_code or "",
    )

    # 5. Prioritized Remediation Roadmap
    _build_remediation_roadmap(
        story=story,
        styles=styles,
        result=result,
        sorted_findings=sorted_findings,
    )

    # 6. Overall Code Quality Assessment
    _build_quality_assessment(
        story=story,
        styles=styles,
        sorted_findings=sorted_findings,
        remediations=remediations,
        health=health,
        language=resolved_language,
    )

    on_first, on_later = _make_page_chrome(resolved_filename, generated_date)
    doc.build(story, onFirstPage=on_first, onLaterPages=on_later)

    pdf_bytes = pdf_buf.getvalue()
    pdf_buf.close()
    return pdf_bytes

