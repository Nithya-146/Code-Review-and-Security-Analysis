"""
Reusable UI Components and Pure Data-Preparation Helpers (Milestone 3 Step 3).

Contains framework-agnostic pure functions for:
- Finding sorting, filtering, and severity counting
- Health score color-coding and grade mapping
- Remediation matching and verification count aggregation
- Inline SVG visualizations (Health Score radial gauge & severity donut chart)
- HTML-safe source code viewer with vulnerable line highlighting
- Markdown / JSON serialization exports
- Input validation and sample code loading

Kept free of Streamlit imports so every helper can be unit tested directly.
"""

import html
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

SEV_COLORS: Dict[str, str] = {
    "CRITICAL": "#EF4444",  # red
    "HIGH": "#F97316",      # orange
    "MEDIUM": "#EAB308",    # amber
    "LOW": "#3B82F6",       # blue
    "INFO": "#6B7280",      # gray
}

EFFORT_COLORS: Dict[str, str] = {
    "Low": "#10B981",       # green
    "Medium": "#EAB308",    # amber
    "High": "#EF4444",      # red
}

MAX_FILE_SIZE_BYTES: int = 1 * 1024 * 1024  # 1 MB
MAX_LINE_COUNT: int = 10000


def _get_val(item: Any, key: str, default: Any = None) -> Any:
    """Safely extracts a field from a dictionary or Pydantic model/object."""
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def extract_severity_str(finding: Any) -> str:
    """Normalizes a finding's severity enum or string to uppercase string."""
    raw = _get_val(finding, "severity", "INFO")
    if hasattr(raw, "value"):
        return str(raw.value).upper()
    return str(raw).split(".")[-1].upper()


def get_health_score_color(score: int) -> str:
    """
    Maps a 0-100 Code Health Score to a dark-theme readable hex color (green to red).
    - 90-100 (Grade A): #10B981 (emerald green)
    - 80-89  (Grade B): #22C55E (green)
    - 70-79  (Grade C): #EAB308 (amber/yellow)
    - 60-69  (Grade D): #F97316 (orange)
    - < 60   (Grade F): #EF4444 (red)
    """
    val = int(score)
    if val >= 90:
        return "#10B981"
    if val >= 80:
        return "#22C55E"
    if val >= 70:
        return "#EAB308"
    if val >= 60:
        return "#F97316"
    return "#EF4444"


def get_health_grade(score: int) -> str:
    """Maps a 0-100 health score to letter grade A-F."""
    val = int(score)
    if val >= 90:
        return "A"
    if val >= 80:
        return "B"
    if val >= 70:
        return "C"
    if val >= 60:
        return "D"
    return "F"


def get_severity_counts(findings: List[Any]) -> Dict[str, int]:
    """
    Computes exact finding counts across CRITICAL, HIGH, MEDIUM, LOW, INFO, and TOTAL.
    """
    counts: Dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 0,
    }
    for f in findings:
        sev = extract_severity_str(f)
        if sev in counts:
            counts[sev] += 1
        else:
            counts["INFO"] += 1
        counts["TOTAL"] += 1
    return counts


def sort_findings(findings: List[Any], sort_by: str = "severity") -> List[Any]:
    """
    Sorts findings deterministically.

    Args:
        findings: List of finding dicts or Finding models.
        sort_by: 'severity' (default), 'line', or 'confidence'.
    """
    if not findings:
        return []

    if sort_by == "line":
        return sorted(
            findings,
            key=lambda f: (
                int(_get_val(f, "line_start", 1) or 1),
                -SEVERITY_ORDER.get(extract_severity_str(f), 0),
            ),
        )
    if sort_by == "confidence":
        return sorted(
            findings,
            key=lambda f: (
                -float(_get_val(f, "confidence", 0.0) or 0.0),
                -SEVERITY_ORDER.get(extract_severity_str(f), 0),
            ),
        )

    # Default: severity descending -> severity_score descending -> line_start ascending
    return sorted(
        findings,
        key=lambda f: (
            -SEVERITY_ORDER.get(extract_severity_str(f), 0),
            -float(_get_val(f, "severity_score", 0.0) or 0.0),
            int(_get_val(f, "line_start", 1) or 1),
        ),
    )


def filter_findings(
    findings: List[Any],
    severities: Optional[List[str]] = None,
    agents: Optional[List[str]] = None,
    categories: Optional[List[str]] = None,
    search_text: str = "",
) -> List[Any]:
    """
    Filters findings by severity tier, source agent, category, and free-text query.
    None values bypass that specific filter; empty lists match zero items for that filter.
    """
    if not findings:
        return []

    sev_set = {s.upper() for s in severities} if severities is not None else None
    agent_set = set(agents) if agents is not None else None
    cat_set = set(categories) if categories is not None else None
    q = (search_text or "").strip().lower()

    filtered: List[Any] = []
    for f in findings:
        sev = extract_severity_str(f)
        if sev_set is not None and sev not in sev_set:
            continue

        agent_val = str(_get_val(f, "agent", ""))
        if agent_set is not None and agent_val not in agent_set:
            continue

        cat_val = str(_get_val(f, "category", ""))
        if cat_set is not None and cat_val not in cat_set:
            continue

        if q:
            searchable = " ".join([
                str(_get_val(f, "id", "")),
                str(_get_val(f, "title", "")),
                str(_get_val(f, "explanation", "")),
                str(_get_val(f, "code_snippet", "")),
                str(_get_val(f, "cwe_id", "")),
                cat_val,
            ]).lower()
            if q not in searchable:
                continue

        filtered.append(f)

    return filtered


def get_verified_remediation_counts(remediations: List[Any]) -> Tuple[int, int]:
    """
    Returns (verified_count, total_remediations_count).
    """
    if not remediations:
        return (0, 0)
    verified = sum(1 for r in remediations if bool(_get_val(r, "verified", False)))
    return (verified, len(remediations))


def map_remediations_by_finding(remediations: List[Any]) -> Dict[str, Any]:
    """
    Builds a fast lookup dict mapping finding_id -> remediation item.
    """
    mapping: Dict[str, Any] = {}
    for rem in remediations or []:
        fid = _get_val(rem, "finding_id", "")
        if fid:
            mapping[str(fid)] = rem
    return mapping


def build_health_gauge_svg(score: int, grade: str) -> str:
    """
    Builds an inline SVG circular ring gauge for the Code Health Score and grade (A-F).
    """
    clamped = max(0, min(100, int(score)))
    color = get_health_score_color(clamped)
    radius = 52
    circumference = 2.0 * math.pi * radius
    dash_offset = circumference * (1.0 - clamped / 100.0)
    safe_grade = html.escape(str(grade).upper()[:2])

    return (
        f"<div style='background:#07101F;border:1px solid #1E3A5F;border-radius:10px;padding:1rem;display:flex;flex-direction:column;align-items:center;justify-content:center;'>"
        f"<svg width='140' height='140' viewBox='0 0 140 140' role='img' aria-label='Code Health Score {clamped} Grade {safe_grade}'>"
        f"<circle cx='70' cy='70' r='{radius}' fill='none' stroke='#1E3A5F' stroke-width='12' />"
        f"<circle cx='70' cy='70' r='{radius}' fill='none' stroke='{color}' stroke-width='12' "
        f"stroke-linecap='round' stroke-dasharray='{circumference:.2f}' stroke-dashoffset='{dash_offset:.2f}' "
        f"transform='rotate(-90 70 70)' />"
        f"<text x='70' y='62' text-anchor='middle' fill='#E6EDF7' font-size='27' font-weight='700'>{clamped}</text>"
        f"<text x='70' y='80' text-anchor='middle' fill='#94A3B8' font-size='10' font-weight='600'>OUT OF 100</text>"
        f"<text x='70' y='103' text-anchor='middle' fill='{color}' font-size='19' font-weight='700'>GRADE {safe_grade}</text>"
        f"</svg>"
        f"</div>"
    )


def build_severity_donut_svg(counts: Dict[str, int]) -> str:
    """
    Builds an inline SVG donut chart with color-coded legend for severity breakdown.
    """
    sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    total = sum(max(0, int(counts.get(s, 0))) for s in sevs)
    radius = 44
    circumference = 2.0 * math.pi * radius

    if total == 0:
        slices_svg = f"<circle cx='60' cy='60' r='{radius}' fill='none' stroke='#10B981' stroke-width='14' />"
        center_val = "0"
        center_sub = "CLEAN"
    else:
        slices: List[str] = []
        offset = 0.0
        for sev in sevs:
            val = max(0, int(counts.get(sev, 0)))
            if val <= 0:
                continue
            seg_len = (val / total) * circumference
            color = SEV_COLORS.get(sev, "#3B82F6")
            slices.append(
                f"<circle cx='60' cy='60' r='{radius}' fill='none' stroke='{color}' stroke-width='14' "
                f"stroke-dasharray='{seg_len:.2f} {circumference:.2f}' stroke-dashoffset='{-offset:.2f}' "
                f"transform='rotate(-90 60 60)' />"
            )
            offset += seg_len
        slices_svg = "".join(slices)
        center_val = str(total)
        center_sub = "ISSUES"

    legend_items: List[str] = []
    for sev in sevs:
        val = max(0, int(counts.get(sev, 0)))
        color = SEV_COLORS.get(sev, "#6B7280")
        legend_items.append(
            f"<div style='display:flex;align-items:center;justify-content:space-between;gap:10px;font-size:0.8rem;margin-bottom:4px;'>"
            f"<span style='display:flex;align-items:center;gap:6px;color:#CBD5E1;'>"
            f"<span style='width:10px;height:10px;border-radius:2px;background:{color};display:inline-block;'></span>{sev}</span>"
            f"<strong style='color:#E6EDF7;'>{val}</strong>"
            f"</div>"
        )

    return (
        f"<div style='display:flex;align-items:center;gap:1.5rem;background:#07101F;border:1px solid #1E3A5F;border-radius:10px;padding:1rem 1.25rem;'>"
        f"<svg width='120' height='120' viewBox='0 0 120 120' style='flex-shrink:0;' role='img' aria-label='Severity distribution donut chart'>"
        f"<circle cx='60' cy='60' r='{radius}' fill='none' stroke='#0D1F3C' stroke-width='14' />"
        f"{slices_svg}"
        f"<text x='60' y='57' text-anchor='middle' fill='#E6EDF7' font-size='20' font-weight='700'>{center_val}</text>"
        f"<text x='60' y='74' text-anchor='middle' fill='#94A3B8' font-size='10' font-weight='600'>{center_sub}</text>"
        f"</svg>"
        f"<div style='flex:1;min-width:120px;'>{''.join(legend_items)}</div>"
        f"</div>"
    )


def build_code_viewer_html(code: str, findings: List[Any]) -> str:
    """
    Renders submitted source code with line numbers and red/amber/blue highlighting
    on vulnerable or defective lines. Escapes all source text for HTML safety.
    """
    if not code or not code.strip():
        return "<div style='color:#94A3B8;font-size:0.85rem;'>No source code submitted to display.</div>"

    line_hits: Dict[int, List[Tuple[str, str]]] = {}
    for f in findings or []:
        sev = extract_severity_str(f)
        fid = str(_get_val(f, "id", ""))
        title = str(_get_val(f, "title", "Finding"))
        l_start = max(1, int(_get_val(f, "line_start", 1) or 1))
        l_end = max(l_start, int(_get_val(f, "line_end", l_start) or l_start))
        label = f"{fid}: {title}" if fid else title
        for ln in range(l_start, l_end + 1):
            line_hits.setdefault(ln, []).append((sev, label))

    rows_html: List[str] = []
    for idx, line_text in enumerate(code.splitlines(), start=1):
        escaped_code = html.escape(line_text) if line_text else " "
        hits = line_hits.get(idx, [])
        if hits:
            top_sev = max(hits, key=lambda h: SEVERITY_ORDER.get(h[0], 0))[0]
            border_color = SEV_COLORS.get(top_sev, "#EF4444")
            bg_tint = (
                "rgba(239, 68, 68, 0.16)"
                if top_sev in ("CRITICAL", "HIGH")
                else "rgba(234, 179, 8, 0.14)"
            )
            hit_labels = ", ".join(html.escape(h[1]) for h in hits[:2])
            tag_html = (
                f"<span style='float:right;color:{border_color};font-size:0.72rem;"
                f"font-weight:600;margin-left:12px;'>⚠ {hit_labels}</span>"
            )
            row_style = f"background:{bg_tint};border-left:3px solid {border_color};"
        else:
            tag_html = ""
            row_style = "border-left:3px solid transparent;"

        rows_html.append(
            f"<div style='display:flex;align-items:baseline;padding:1px 8px;font-family:monospace;"
            f"font-size:0.82rem;line-height:1.5;{row_style}'>"
            f"<span style='min-width:36px;color:#64748B;user-select:none;text-align:right;padding-right:12px;'>{idx}</span>"
            f"<span style='white-space:pre;color:#E6EDF7;flex:1;overflow-x:auto;'>{escaped_code}</span>"
            f"{tag_html}"
            f"</div>"
        )

    return (
        "<div style='background:#050B14;border:1px solid #1E3A5F;border-radius:8px;"
        "padding:0.5rem 0;max-height:420px;overflow-y:auto;'>"
        + "".join(rows_html)
        + "</div>"
    )


def export_results_json(analysis_result: Any) -> str:
    """Serializes an AnalysisResult (dict or Pydantic model) into formatted JSON text."""
    if hasattr(analysis_result, "model_dump"):
        payload = analysis_result.model_dump()
    elif isinstance(analysis_result, dict):
        payload = analysis_result
    else:
        payload = {"result": str(analysis_result)}
    return json.dumps(payload, indent=2, default=str)


def export_pr_markdown(analysis_result: Any) -> str:
    """
    Extracts the PR-style markdown report from an AnalysisResult,
    or falls back to generating a structured markdown summary from findings.
    """
    if hasattr(analysis_result, "model_dump"):
        data = analysis_result.model_dump()
    elif isinstance(analysis_result, dict):
        data = analysis_result
    else:
        data = {}

    pr_summary = data.get("pr_summary")
    if isinstance(pr_summary, dict) and pr_summary.get("markdown"):
        return str(pr_summary["markdown"])

    filename = data.get("filename", "submission")
    findings = data.get("findings", [])
    counts = get_severity_counts(findings)
    lines = [
        f"# Pull Request Security & Quality Review: `{filename}`",
        "",
        f"**Total Findings:** {counts['TOTAL']} "
        f"(Critical: {counts['CRITICAL']}, High: {counts['HIGH']}, "
        f"Medium: {counts['MEDIUM']}, Low: {counts['LOW']}, Info: {counts['INFO']})",
        "",
    ]
    for f in findings:
        sev = extract_severity_str(f)
        title = _get_val(f, "title", "Finding")
        l_start = _get_val(f, "line_start", 1)
        expl = _get_val(f, "explanation", "")
        lines.append(f"- **[{sev}] {title}** (Line {l_start}): {expl}")
    return "\n".join(lines)


def validate_submission_input(
    code: Optional[str],
    language: str,
    max_bytes: int = MAX_FILE_SIZE_BYTES,
    max_lines: int = MAX_LINE_COUNT,
) -> Tuple[bool, Optional[str]]:
    """
    Validates user code submission before syntax/agent execution.
    Returns (is_valid, friendly_error_message_or_None).
    """
    if not code or not code.strip():
        return (False, "⚠️ Please paste or upload Python or Java source code before analyzing.")

    norm_lang = (language or "").strip().lower()
    if norm_lang not in ("python", "py", "java"):
        return (False, f"❌ Unsupported language '{language}'. Supported languages: Python, Java.")

    byte_size = len(code.encode("utf-8", errors="ignore"))
    if byte_size > max_bytes:
        mb = byte_size / (1024 * 1024)
        return (False, f"❌ Submission size ({mb:.2f} MB) exceeds the 1 MB maximum limit.")

    line_count = len(code.splitlines())
    if line_count > max_lines:
        return (False, f"⚠️ Submission has {line_count} lines, exceeding the {max_lines}-line analysis limit.")

    return (True, None)


def load_sample_code(language: str, project_root: Optional[Path] = None) -> Tuple[str, str]:
    """
    Loads the built-in vulnerable Python or Java sample file from tests/samples/.
    Returns (source_code, filename).
    """
    root = project_root or Path(__file__).resolve().parent.parent
    norm_lang = (language or "").strip().lower()
    if norm_lang in ("java",):
        path = root / "tests" / "samples" / "java" / "PlantedSecurity.java"
        fname = "PlantedSecurity.java"
    else:
        path = root / "tests" / "samples" / "python" / "planted_security.py"
        fname = "planted_security.py"

    if path.exists():
        return (path.read_text(encoding="utf-8"), fname)
    return ("", fname)


def badge_html(severity: str) -> str:
    """Returns an escaped HTML severity badge pill."""
    sev = html.escape(str(severity).upper().strip() or "INFO")
    return f"<span class='badge badge-{sev}'>{sev}</span>"


def verified_badge_html(verified: bool) -> str:
    """Returns a green verified or amber unverified pill badge."""
    if verified:
        return (
            "<span style='display:inline-block;padding:2px 10px;border-radius:9999px;"
            "font-size:0.74rem;font-weight:700;background:#064E3B;color:#10B981;"
            "border:1px solid #10B981;'>✅ VERIFIED FIX</span>"
        )
    return (
        "<span style='display:inline-block;padding:2px 10px;border-radius:9999px;"
        "font-size:0.74rem;font-weight:700;background:#422006;color:#EAB308;"
        "border:1px solid #EAB308;'>⚠️ MANUAL REVIEW NEEDED</span>"
    )


def grounding_badge_html(grounded: bool) -> str:
    """Returns a KB grounding status indicator badge for assistant answers."""
    if grounded:
        return (
            "<span style='display:inline-block;padding:2px 10px;border-radius:9999px;"
            "font-size:0.72rem;font-weight:700;background:#064E3B;color:#10B981;"
            "border:1px solid #10B981;'>📚 Grounded in Knowledge Base</span>"
        )
    return (
        "<span style='display:inline-block;padding:2px 10px;border-radius:9999px;"
        "font-size:0.72rem;font-weight:700;background:#422006;color:#EAB308;"
        "border:1px solid #EAB308;'>ℹ️ Not covered by Knowledge Base</span>"
    )


def build_prioritized_fixes_table_html(prioritized_fixes: List[Any]) -> str:
    """
    Renders the PR Summary prioritized fix list as a dark-theme HTML table
    with columns: Order, Finding, Severity, Effort, Why First.
    """
    if not prioritized_fixes:
        return (
            "<div style='background:#07101F;border:1px solid #1E3A5F;border-radius:8px;"
            "padding:1rem;color:#10B981;font-size:0.9rem;'>"
            "✅ No actionable defects require remediation.</div>"
        )

    rows: List[str] = []
    for idx, item in enumerate(prioritized_fixes, start=1):
        fid = html.escape(str(_get_val(item, "finding_id", "")))
        title = html.escape(str(_get_val(item, "title", "Finding")))
        sev = extract_severity_str(item)
        effort = html.escape(str(_get_val(item, "effort", "Medium")))
        reason = html.escape(str(_get_val(item, "reason", "")))
        eff_color = EFFORT_COLORS.get(effort, "#94A3B8")

        finding_label = f"<code>{fid}</code> {title}" if fid else title
        rows.append(
            f"<tr>"
            f"<td class='num-col' style='text-align:center !important;width:64px;'>{idx}</td>"
            f"<td>{finding_label}</td>"
            f"<td>{badge_html(sev)}</td>"
            f"<td><span style='color:{eff_color};font-weight:700;'>{effort}</span></td>"
            f"<td style='color:#CBD5E1;'>{reason}</td>"
            f"</tr>"
        )

    return (
        "<table class='report-table'>"
        "<thead><tr>"
        "<th style='text-align:center;width:64px;'>Order</th>"
        "<th>Finding</th>"
        "<th>Severity</th>"
        "<th>Effort</th>"
        "<th>Why First</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )
