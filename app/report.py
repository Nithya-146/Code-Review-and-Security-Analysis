"""
Report generation module for AI Code Review & Security Analysis Agent.

Builds structured final review reports from AnalysisResult:
- Overall risk rating (Critical, High, Medium, Low, or No issues found)
- File summary metrics
- Security summary by OWASP category
- Code quality summary by rule/category
- Top 5 issues to fix first
- Recommended next steps (deduplicated actionable suggestions)
- In-memory Markdown and self-contained HTML export generators
"""

from typing import Any, Dict, List, Optional, Sequence, Tuple
import html


SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

SEV_COLORS: Dict[str, str] = {
    "CRITICAL": "#EF4444",
    "HIGH": "#F97316",
    "MEDIUM": "#EAB308",
    "LOW": "#3B82F6",
    "INFO": "#6B7280",
    "CLEAN": "#10B981",
}


def _get_val(item: Any, key: str, default: Any = None) -> Any:
    """Extracts attribute or dictionary value uniformly."""
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _get_severity_str(item: Any) -> str:
    """Normalizes severity level to uppercase string."""
    raw = _get_val(item, "severity", "INFO")
    if hasattr(raw, "value"):
        return str(raw.value).upper()
    return str(raw).split(".")[-1].upper()


def _get_severity_score(item: Any) -> float:
    """Extracts numeric severity score."""
    try:
        return float(_get_val(item, "severity_score", 0.0))
    except (ValueError, TypeError):
        return 0.0


def calculate_risk_rating(findings: Sequence[Any]) -> Tuple[str, str, str]:
    """
    Computes overall risk rating from a list of findings.

    Rules:
    - Critical if any Critical finding exists
    - High if any High finding exists
    - Medium if any Medium finding exists
    - Otherwise Low (if findings exist)
    - "No issues found" when the list is empty

    Returns:
        Tuple of (risk_level, reason_sentence, hex_color)
    """
    if not findings:
        return ("No issues found", "No security or code quality issues were identified.", SEV_COLORS["CLEAN"])

    sev_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        s = _get_severity_str(f)
        sev_counts[s] = sev_counts.get(s, 0) + 1

    crit = sev_counts.get("CRITICAL", 0)
    high = sev_counts.get("HIGH", 0)
    med = sev_counts.get("MEDIUM", 0)
    low = sev_counts.get("LOW", 0)
    info = sev_counts.get("INFO", 0)

    if crit > 0:
        plural = "vulnerabilities need" if crit > 1 else "vulnerability needs"
        reason = f"{crit} critical {plural} fixing before this code is used."
        return ("Critical", reason, SEV_COLORS["CRITICAL"])

    if high > 0:
        plural = "issues need" if high > 1 else "issue needs"
        reason = f"{high} high-severity {plural} attention before production deployment."
        return ("High", reason, SEV_COLORS["HIGH"])

    if med > 0:
        plural = "issues" if med > 1 else "issue"
        reason = f"{med} medium-severity {plural} found that should be addressed."
        return ("Medium", reason, SEV_COLORS["MEDIUM"])

    if low > 0:
        plural = "issues" if low > 1 else "issue"
        reason = f"{low} low-severity {plural} identified."
        return ("Low", reason, SEV_COLORS["LOW"])

    return ("Low", f"{info} informational notice(s) identified.", SEV_COLORS["LOW"])


def get_top_findings(findings: Sequence[Any], limit: int = 5) -> List[Any]:
    """
    Returns up to `limit` highest-severity findings ordered by:
    1. Severity weight descending (CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO)
    2. Severity score descending (10.0 -> 0.0)
    3. Starting line number ascending
    """
    if not findings:
        return []

    sorted_findings = sorted(
        findings,
        key=lambda f: (
            -SEVERITY_WEIGHTS.get(_get_severity_str(f), 0),
            -_get_severity_score(f),
            int(_get_val(f, "line_start", 1)),
        ),
    )
    return sorted_findings[:limit]


def get_security_summary(findings: Sequence[Any]) -> Dict[str, int]:
    """Counts security findings per readable OWASP category."""
    summary: Dict[str, int] = {}
    for f in findings:
        raw_owasp = _get_val(f, "owasp_category")
        if not raw_owasp:
            continue
        val = raw_owasp.value if hasattr(raw_owasp, "value") else str(raw_owasp)
        if "OWASPCategory." in val:
            val = val.split("OWASPCategory.")[-1]
        readable = val.replace("-", " ", 1).strip()
        summary[readable] = summary.get(readable, 0) + 1
    return summary


def get_quality_summary(findings: Sequence[Any]) -> Dict[str, int]:
    """Counts quality findings per code quality category/rule."""
    summary: Dict[str, int] = {}
    for f in findings:
        # Skip security findings
        agent = _get_val(f, "agent", "")
        if agent == "security_analysis" or _get_val(f, "owasp_category"):
            continue

        evidence = _get_val(f, "evidence") or ""
        if "Static AST Check: " in evidence:
            rule = evidence.split("Static AST Check: ")[-1].strip()
            category = rule.replace("_", " ").title()
        else:
            title = _get_val(f, "title", "Code Quality")
            category = title.strip()

        summary[category] = summary.get(category, 0) + 1
    return summary


def get_recommended_steps(findings: Sequence[Any], max_steps: int = 5) -> List[str]:
    """
    Extracts 3-5 unique, actionable recommendations from findings suggestions.
    Ordered by finding severity.
    """
    if not findings:
        return ["Code is clean. No remediation actions required."]

    top_sorted = get_top_findings(findings, limit=len(findings))
    steps: List[str] = []
    seen: set = set()

    for f in top_sorted:
        sugg = _get_val(f, "suggestion")
        if not sugg:
            continue
        sugg_clean = str(sugg).strip()
        if not sugg_clean:
            continue
        # Extract first sentence or full suggestion
        first_clause = sugg_clean.split("\n")[0].strip()
        key = first_clause.lower()
        if key not in seen:
            seen.add(key)
            steps.append(first_clause)
        if len(steps) >= max_steps:
            break

    if not steps:
        steps.append("Address the identified findings according to code standards.")
    return steps


def build_report_data(
    result: Any,
    lines_of_code: Optional[int] = None,
    filename: Optional[str] = None,
    language: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Extracts and standardizes all data needed for final report rendering and export.
    """
    findings = _get_val(result, "findings", []) or []
    counts_by_sev = _get_val(result, "counts_by_severity", {}) or {}

    file_name = filename or _get_val(result, "filename", "unknown")
    lang = language or _get_val(result, "language", "python")

    if lines_of_code is None:
        loc = max((int(_get_val(f, "line_end", 1)) for f in findings), default=0) if findings else 0
    else:
        loc = lines_of_code

    risk_level, risk_reason, risk_color = calculate_risk_rating(findings)
    top_5 = get_top_findings(findings, limit=5)
    sec_summary = get_security_summary(findings)
    qual_summary = get_quality_summary(findings)
    next_steps = get_recommended_steps(findings, max_steps=5)

    return {
        "filename": file_name,
        "language": lang,
        "lines_of_code": loc,
        "total_findings": len(findings),
        "counts_by_severity": counts_by_sev,
        "risk_level": risk_level,
        "risk_reason": risk_reason,
        "risk_color": risk_color,
        "top_5": top_5,
        "security_summary": sec_summary,
        "quality_summary": qual_summary,
        "recommended_steps": next_steps,
        "all_findings": findings,
    }


def generate_markdown_report(report_data: Dict[str, Any]) -> str:
    """Generates an in-memory Markdown report representation."""
    md = []
    fname = report_data.get("filename", "unknown")
    lang = report_data.get("language", "python").capitalize()
    loc = report_data.get("lines_of_code", 0)
    total = report_data.get("total_findings", 0)

    md.append(f"# AI Code Review & Security Analysis Report")
    md.append(f"**Target File:** `{fname}` | **Language:** {lang} | **Lines of Code:** {loc}\n")
    md.append("---\n")

    # 1. Overall Risk Rating
    risk_level = report_data.get("risk_level", "Low")
    risk_reason = report_data.get("risk_reason", "")
    md.append(f"## 1. Overall Risk Rating: **{risk_level.upper()}**")
    md.append(f"> {risk_reason}\n")

    # 2. File Summary
    counts = report_data.get("counts_by_severity", {})
    md.append("## 2. File Summary")
    md.append(f"- **Total Findings:** {total}")
    md.append(f"- **Critical:** {counts.get('CRITICAL', 0)}")
    md.append(f"- **High:** {counts.get('HIGH', 0)}")
    md.append(f"- **Medium:** {counts.get('MEDIUM', 0)}")
    md.append(f"- **Low:** {counts.get('LOW', 0)}")
    md.append(f"- **Info:** {counts.get('INFO', 0)}\n")

    # 3. Security Summary
    sec = report_data.get("security_summary", {})
    md.append("## 3. Security Summary (OWASP Top 10:2025)")
    if sec:
        md.append("| OWASP Category | Finding Count |")
        md.append("| :--- | :---: |")
        for cat, count in sec.items():
            md.append(f"| {cat} | {count} |")
    else:
        md.append("*(No security vulnerabilities detected)*")
    md.append("")

    # 4. Code Quality Summary
    qual = report_data.get("quality_summary", {})
    md.append("## 4. Code Quality Summary")
    if qual:
        md.append("| Quality Category | Finding Count |")
        md.append("| :--- | :---: |")
        for cat, count in qual.items():
            md.append(f"| {cat} | {count} |")
    else:
        md.append("*(No code quality defects detected)*")
    md.append("")

    # 5. Top 5 Issues
    top_5 = report_data.get("top_5", [])
    md.append("## 5. Top Issues to Fix First")
    if top_5:
        for idx, f in enumerate(top_5, 1):
            sev = _get_severity_str(f)
            title = _get_val(f, "title", "Finding")
            l_start = _get_val(f, "line_start", 1)
            l_end = _get_val(f, "line_end", l_start)
            line_str = f"Line {l_start}" if l_start == l_end else f"Lines {l_start}–{l_end}"
            md.append(f"{idx}. **[{sev}]** {title} — {line_str}")
    else:
        md.append("*(No issues to fix)*")
    md.append("")

    # 6. Recommended Next Steps
    steps = report_data.get("recommended_steps", [])
    md.append("## 6. Recommended Next Steps")
    for s in steps:
        md.append(f"- {s}")
    md.append("")

    return "\n".join(md)


def generate_html_report(report_data: Dict[str, Any]) -> str:
    """
    Generates a completely self-contained HTML report with black and blue theme.
    No external dependencies, fonts, or scripts.
    """
    fname = html.escape(str(report_data.get("filename", "unknown")))
    lang = html.escape(str(report_data.get("language", "python")).capitalize())
    loc = report_data.get("lines_of_code", 0)
    total = report_data.get("total_findings", 0)

    risk_level = report_data.get("risk_level", "Low")
    risk_reason = html.escape(str(report_data.get("risk_reason", "")))
    risk_color = report_data.get("risk_color", "#3B82F6")

    counts = report_data.get("counts_by_severity", {})
    sec = report_data.get("security_summary", {})
    qual = report_data.get("quality_summary", {})
    top_5 = report_data.get("top_5", [])
    steps = report_data.get("recommended_steps", [])

    badge_classes = {
        "CRITICAL": "badge-CRITICAL",
        "HIGH": "badge-HIGH",
        "MEDIUM": "badge-MEDIUM",
        "LOW": "badge-LOW",
        "INFO": "badge-INFO",
        "No issues found": "badge-CLEAN",
    }
    risk_badge_cls = badge_classes.get(risk_level, "badge-LOW")

    # Render top 5 items
    top_5_html = ""
    if top_5:
        items = []
        for f in top_5:
            sev = _get_severity_str(f)
            title = html.escape(str(_get_val(f, "title", "Finding")))
            l_start = _get_val(f, "line_start", 1)
            l_end = _get_val(f, "line_end", l_start)
            line_str = f"Line {l_start}" if l_start == l_end else f"Lines {l_start}–{l_end}"
            items.append(
                f"<li class='top-item'><span class='badge badge-{sev}'>{sev}</span> "
                f"<strong>{title}</strong> <span class='line-meta'>({line_str})</span></li>"
            )
        top_5_html = f"<ol class='top-list'>{''.join(items)}</ol>"
    else:
        top_5_html = "<p class='empty-text'>🎉 No issues found — code is clean.</p>"

    # Render Security Table
    if sec:
        sec_rows = "".join(
            f"<tr><td>{html.escape(k)}</td><td class='num-col'>{v}</td></tr>"
            for k, v in sec.items()
        )
        sec_table_html = (
            f"<table class='summary-table'>"
            f"<thead><tr><th>OWASP Category</th><th class='num-col'>Findings</th></tr></thead>"
            f"<tbody>{sec_rows}</tbody></table>"
        )
    else:
        sec_table_html = "<p class='empty-text'>No security vulnerabilities detected.</p>"

    # Render Quality Table
    if qual:
        qual_rows = "".join(
            f"<tr><td>{html.escape(k)}</td><td class='num-col'>{v}</td></tr>"
            for k, v in qual.items()
        )
        qual_table_html = (
            f"<table class='summary-table'>"
            f"<thead><tr><th>Quality Category</th><th class='num-col'>Findings</th></tr></thead>"
            f"<tbody>{qual_rows}</tbody></table>"
        )
    else:
        qual_table_html = "<p class='empty-text'>No code quality defects detected.</p>"

    # Render Recommended steps
    steps_html = "".join(f"<li>{html.escape(s)}</li>" for s in steps)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Analysis Report — {fname}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background-color: #000000;
    color: #E6EDF7;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.5;
    padding: 2rem 1rem;
  }}
  .container {{
    max-width: 900px;
    margin: 0 auto;
    background-color: #07101F;
    border: 1px solid #1E3A5F;
    border-radius: 10px;
    padding: 2.2rem;
  }}
  .header {{
    border-bottom: 2px solid #3B82F6;
    padding-bottom: 1.2rem;
    margin-bottom: 1.8rem;
  }}
  .header h1 {{
    font-size: 1.7rem;
    color: #E6EDF7;
    margin-bottom: 0.3rem;
  }}
  .header p {{
    color: #94A3B8;
    font-size: 0.9rem;
  }}
  .section {{
    margin-bottom: 2rem;
  }}
  .section-title {{
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #3B82F6;
    margin-bottom: 0.75rem;
    font-weight: 700;
    border-bottom: 1px solid #1E3A5F;
    padding-bottom: 0.35rem;
  }}
  .risk-card {{
    background: #0D1F3C;
    border-left: 4px solid {risk_color};
    border-radius: 6px;
    padding: 1.1rem 1.3rem;
    display: flex;
    align-items: center;
    gap: 1.2rem;
  }}
  .risk-reason {{
    font-size: 1rem;
    color: #E6EDF7;
  }}
  .grid-5 {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 0.75rem;
    margin-top: 0.8rem;
  }}
  .metric-tile {{
    background: #000000;
    border: 1px solid #1E3A5F;
    border-radius: 6px;
    padding: 0.8rem;
    text-align: center;
  }}
  .metric-val {{
    font-size: 1.5rem;
    font-weight: 700;
  }}
  .metric-lbl {{
    font-size: 0.7rem;
    color: #94A3B8;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .file-meta {{
    font-size: 0.9rem;
    color: #94A3B8;
    margin-bottom: 0.6rem;
  }}
  .summary-table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 0.5rem;
    font-size: 0.88rem;
  }}
  .summary-table th, .summary-table td {{
    padding: 0.6rem 0.8rem;
    border: 1px solid #1E3A5F;
    text-align: left;
  }}
  .summary-table th {{
    background-color: #0D1F3C;
    color: #E6EDF7;
  }}
  .summary-table td {{
    background-color: #000000;
  }}
  .num-col {{
    text-align: right !important;
    width: 90px;
    font-weight: 600;
  }}
  .badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 9999px;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }}
  .badge-CRITICAL {{ background:#3B0A0A; color:#EF4444; border:1px solid #EF4444; }}
  .badge-HIGH     {{ background:#431407; color:#F97316; border:1px solid #F97316; }}
  .badge-MEDIUM   {{ background:#422006; color:#EAB308; border:1px solid #EAB308; }}
  .badge-LOW      {{ background:#0D1F3C; color:#3B82F6; border:1px solid #3B82F6; }}
  .badge-INFO     {{ background:#111827; color:#9CA3AF; border:1px solid #374151; }}
  .badge-CLEAN    {{ background:#064E3B; color:#10B981; border:1px solid #10B981; }}
  .top-list {{
    list-style: none;
    padding: 0;
  }}
  .top-item {{
    background: #000000;
    border: 1px solid #1E3A5F;
    border-radius: 6px;
    padding: 0.7rem 1rem;
    margin-bottom: 0.45rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    font-size: 0.88rem;
  }}
  .line-meta {{
    color: #94A3B8;
    font-size: 0.8rem;
  }}
  .steps-list {{
    padding-left: 1.4rem;
    color: #CBD5E1;
    font-size: 0.9rem;
  }}
  .steps-list li {{
    margin-bottom: 0.45rem;
  }}
  .empty-text {{
    color: #64748B;
    font-size: 0.88rem;
    font-style: italic;
  }}
  .footer {{
    margin-top: 2.5rem;
    border-top: 1px solid #1E3A5F;
    padding-top: 1rem;
    font-size: 0.75rem;
    color: #64748B;
    text-align: center;
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🛡️ AI Code Review &amp; Security Analysis Report</h1>
    <p>Target: <strong>{fname}</strong> &nbsp;|&nbsp; Language: <strong>{lang}</strong> &nbsp;|&nbsp; Lines of Code: <strong>{loc}</strong></p>
  </div>

  <div class="section">
    <div class="section-title">1. Overall Risk Rating</div>
    <div class="risk-card">
      <span class="badge {risk_badge_cls}" style="font-size: 0.95rem; padding: 6px 14px;">{html.escape(risk_level)}</span>
      <span class="risk-reason">{risk_reason}</span>
    </div>
  </div>

  <div class="section">
    <div class="section-title">2. File Summary</div>
    <div class="file-meta">
      <strong>File:</strong> {fname} &nbsp;|&nbsp; 
      <strong>Language:</strong> {lang} &nbsp;|&nbsp; 
      <strong>Lines of Code:</strong> {loc} &nbsp;|&nbsp; 
      <strong>Total Findings:</strong> {total}
    </div>
    <div class="grid-5">
      <div class="metric-tile" style="border-top: 3px solid #EF4444;"><div class="metric-val" style="color:#EF4444;">{counts.get("CRITICAL", 0)}</div><div class="metric-lbl">Critical</div></div>
      <div class="metric-tile" style="border-top: 3px solid #F97316;"><div class="metric-val" style="color:#F97316;">{counts.get("HIGH", 0)}</div><div class="metric-lbl">High</div></div>
      <div class="metric-tile" style="border-top: 3px solid #EAB308;"><div class="metric-val" style="color:#EAB308;">{counts.get("MEDIUM", 0)}</div><div class="metric-lbl">Medium</div></div>
      <div class="metric-tile" style="border-top: 3px solid #3B82F6;"><div class="metric-val" style="color:#3B82F6;">{counts.get("LOW", 0)}</div><div class="metric-lbl">Low</div></div>
      <div class="metric-tile" style="border-top: 3px solid #6B7280;"><div class="metric-val" style="color:#6B7280;">{counts.get("INFO", 0)}</div><div class="metric-lbl">Info</div></div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">3. Security Summary (OWASP Top 10:2025)</div>
    {sec_table_html}
  </div>

  <div class="section">
    <div class="section-title">4. Code Quality Summary</div>
    {qual_table_html}
  </div>

  <div class="section">
    <div class="section-title">5. Top Issues to Fix First</div>
    {top_5_html}
  </div>

  <div class="section">
    <div class="section-title">6. Recommended Next Steps</div>
    <ul class="steps-list">
      {steps_html}
    </ul>
  </div>

  <div class="footer">
    Generated automatically by AI Code Review &amp; Security Analysis Agent (Milestone 2)
  </div>
</div>
</body>
</html>
"""

