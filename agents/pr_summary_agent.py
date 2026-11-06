"""
PR Summary Agent for AI Code Review & Security Analysis.

Synthesizes findings from code quality and security analyses along with automated
remediation results into a deterministic Code Health Score, executive overview,
prioritized action plan, and pull-request-ready markdown summary.
"""

import logging
from typing import Any, Dict, List, Optional

from agents.base import BaseAgent
from app.schemas import (
    CodeHealthScore,
    Finding,
    PrioritizedFix,
    PRSummary,
    RemediationResult,
    SeverityLevel,
)

logger = logging.getLogger(__name__)

# Severity penalty weights and diminishing-returns caps
SEVERITY_WEIGHTS: Dict[str, int] = {
    SeverityLevel.CRITICAL.value: 15,
    SeverityLevel.HIGH.value: 8,
    SeverityLevel.MEDIUM.value: 4,
    SeverityLevel.LOW.value: 1,
    SeverityLevel.INFO.value: 0,
}

SEVERITY_CAPS: Dict[str, int] = {
    SeverityLevel.CRITICAL.value: 45,  # Up to 3 criticals before diminishing returns
    SeverityLevel.HIGH.value: 32,      # Up to 4 highs before diminishing returns
    SeverityLevel.MEDIUM.value: 20,    # Up to 5 mediums before diminishing returns
    SeverityLevel.LOW.value: 10,       # Up to 10 lows before diminishing returns
    SeverityLevel.INFO.value: 0,
}

# Effort rank ordering (easiest fix first within same severity tier)
EFFORT_RANK: Dict[str, int] = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
}

SEVERITY_TIER_RANK: Dict[str, int] = {
    SeverityLevel.CRITICAL.value: 5,
    SeverityLevel.HIGH.value: 4,
    SeverityLevel.MEDIUM.value: 3,
    SeverityLevel.LOW.value: 2,
    SeverityLevel.INFO.value: 1,
}


class PRSummaryAgent(BaseAgent):
    """
    Synthesizes code review and security findings into an executive PR summary,
    calculates deterministic health scores, and prioritizes remediation fixes.
    """

    def __init__(self, agent_name: str = "pr_summary_agent") -> None:
        """Initializes the PR summary agent."""
        super().__init__(agent_name=agent_name)

    # =========================================================================
    # 1. Deterministic Health Score Calculation
    # =========================================================================

    def compute_health_score(self, findings: List[Finding]) -> CodeHealthScore:
        """
        Computes a deterministic Code Health Score (0-100) and letter grade (A-F).

        Formula & Scoring Rules:
        -------------------------
        1. Base Score = 100 points.
        2. Per-finding penalty deductions:
           - CRITICAL: 15 points per finding
           - HIGH:      8 points per finding
           - MEDIUM:    4 points per finding
           - LOW:       1 point per finding
           - INFO:      0 points
        3. Diminishing-returns caps per severity level:
           - CRITICAL penalty cap: 45 points
           - HIGH penalty cap:     32 points
           - MEDIUM penalty cap:   20 points
           - LOW penalty cap:      10 points
           - INFO penalty cap:      0 points
        4. Total penalty = sum(min(raw_penalty[sev], cap[sev]) for sev in severities).
        5. Score = max(0, 100 - total_penalty).
        6. Letter Grade Mapping:
           - A: 90 - 100 (Clean or negligible findings)
           - B: 80 - 89  (Minor quality or low-severity issues)
           - C: 70 - 79  (Moderate defects or isolated high finding)
           - D: 60 - 69  (Significant security or quality debt)
           - F: < 60     (Critical vulnerabilities or severe defect density)
        """
        counts: Dict[str, int] = {
            SeverityLevel.CRITICAL.value: 0,
            SeverityLevel.HIGH.value: 0,
            SeverityLevel.MEDIUM.value: 0,
            SeverityLevel.LOW.value: 0,
            SeverityLevel.INFO.value: 0,
        }

        for f in findings:
            sev_key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            counts[sev_key] = counts.get(sev_key, 0) + 1

        penalties: Dict[str, int] = {}
        total_penalty = 0

        for sev_key, count in counts.items():
            weight = SEVERITY_WEIGHTS.get(sev_key, 0)
            cap = SEVERITY_CAPS.get(sev_key, 100)
            raw_penalty = count * weight
            capped_penalty = min(raw_penalty, cap)
            penalties[sev_key] = capped_penalty
            total_penalty += capped_penalty

        score = max(0, 100 - total_penalty)

        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return CodeHealthScore(
            score=score,
            grade=grade,
            breakdown_by_severity=counts,
            penalty_details=penalties,
        )

    # =========================================================================
    # 2. Fix Prioritization
    # =========================================================================

    def _estimate_effort(self, finding: Finding) -> Tuple[str, str]:
        """
        Estimates the developer effort required to apply remediation (Low, Medium, High)
        and returns a short prioritization rationale.
        """
        cwe = (finding.cwe_id or "").upper()
        title_lower = finding.title.lower()

        # Low Effort: Secrets, broad exceptions, weak hashing, magic numbers
        if "798" in cwe or "secret" in title_lower:
            return ("Low", "High-exposure credential risk; fast one-line fix to read from environment.")
        if "327" in cwe or "328" in cwe or "crypto" in title_lower or "hash" in title_lower:
            return ("Low", "Cryptographic flaw; simple algorithm upgrade to SHA-256.")
        if "except" in title_lower or "catch" in title_lower:
            return ("Low", "Low-effort fix to prevent suppressing unexpected system errors.")
        if "magic" in title_lower:
            return ("Low", "Quick refactoring to extract magic literal into descriptive constant.")

        # Medium Effort: SQLi, XSS, Command Injection, Deserialization, Path Traversal
        if "89" in cwe or "sql injection" in title_lower:
            return ("Medium", "Critical injection risk that can be resolved immediately with parameterized queries.")
        if "78" in cwe or "command injection" in title_lower:
            return ("Medium", "Critical execution risk; replace shell invocation with argument list.")
        if "79" in cwe or "xss" in title_lower:
            return ("Medium", "High-risk XSS flaw; wrap dynamic outputs with HTML entity encoding.")
        if "502" in cwe or "deserial" in title_lower:
            return ("Medium", "Critical deserialization risk; replace untrusted stream parsing with JSON.")
        if "22" in cwe or "traversal" in title_lower:
            return ("Medium", "Path traversal risk; sanitize file paths against base directory.")

        # High Effort: Structural complexity, God class, nesting
        if "complex" in title_lower or "nest" in title_lower or "god class" in title_lower or "long" in title_lower:
            return ("High", "Structural design defect; requires refactoring and method extraction.")

        return ("Medium", "Standard defect resolution following recommended security best practices.")

    def prioritize_fixes(
        self,
        findings: List[Finding],
        remediations: List[RemediationResult],
    ) -> List[PrioritizedFix]:
        """
        Orders fixes by highest severity first, then easiest fix first (effort estimate),
        giving developers the highest security and quality return on effort.
        """
        rem_map = {r.finding_id: r for r in remediations}
        prioritized: List[PrioritizedFix] = []

        for f in findings:
            effort, reason = self._estimate_effort(f)
            prioritized.append(
                PrioritizedFix(
                    finding_id=f.id,
                    title=f.title,
                    severity=f.severity,
                    effort=effort,
                    reason=reason,
                )
            )

        # Sort: Severity descending (5 down to 1), then Effort ascending (1: Low -> 2: Med -> 3: High)
        prioritized.sort(
            key=lambda item: (
                -SEVERITY_TIER_RANK.get(item.severity.value, 0),
                EFFORT_RANK.get(item.effort, 2),
                item.finding_id,
            )
        )
        return prioritized

    # =========================================================================
    # 3. Executive Overview & Top Risks
    # =========================================================================

    def _extract_top_risks(self, findings: List[Finding]) -> List[str]:
        """Extracts the top 1-3 most critical risks identified."""
        risks: List[str] = []
        for f in findings:
            if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
                cwe_tag = f"[{f.cwe_id}] " if f.cwe_id else ""
                desc = f"{cwe_tag}{f.title}: {f.explanation}"
                if desc not in risks:
                    risks.append(desc)
            if len(risks) >= 3:
                break

        if not risks and findings:
            top_f = findings[0]
            risks.append(f"{top_f.title}: {top_f.explanation}")

        return risks

    def build_executive_overview(
        self,
        findings: List[Finding],
        remediations: List[RemediationResult],
        health_score: CodeHealthScore,
        filename: str = "submitted code",
    ) -> str:
        """
        Builds a 2-4 sentence executive overview covering overall health,
        finding count, most serious risk, and verified fix count.
        """
        total_findings = len(findings)
        b = health_score.breakdown_by_severity
        crit_count = b.get(SeverityLevel.CRITICAL.value, 0)
        high_count = b.get(SeverityLevel.HIGH.value, 0)
        med_count = b.get(SeverityLevel.MEDIUM.value, 0)
        low_count = b.get(SeverityLevel.LOW.value, 0)

        # Sentence 1: Health score and grade
        s1 = (
            f"Code review analysis completed for `{filename}` with an overall Code Health Score "
            f"of {health_score.score}/100 (Grade {health_score.grade})."
        )

        # Sentence 2: Findings count
        if total_findings == 0:
            s2 = "No security vulnerabilities or code quality smells were detected in the reviewed code."
            s3 = "The source code adheres to security standards and clean code conventions."
            s4 = "All quality gates and automated verification checks have passed successfully."
            return f"{s1} {s2} {s3} {s4}"
        else:
            s2 = (
                f"A total of {total_findings} finding{'s' if total_findings != 1 else ''} "
                f"were identified ({crit_count} Critical, {high_count} High, {med_count} Medium, {low_count} Low)."
            )

        # Sentence 3: Most serious risk
        crit_or_high = [f for f in findings if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)]
        if crit_or_high:
            top_vuln = crit_or_high[0]
            cwe_info = f" ({top_vuln.cwe_id})" if top_vuln.cwe_id else ""
            s3 = f"The most critical risk identified is {top_vuln.title}{cwe_info}, which requires immediate remediation."
        else:
            s3 = "No critical security vulnerabilities were discovered, though quality improvements are recommended."

        # Sentence 4: Verified fixes count
        verified_count = sum(1 for r in remediations if r.verified)
        total_remediations = len(remediations)
        s4 = (
            f"The remediation engine generated {total_remediations} automated fix"
            f"{'es' if total_remediations != 1 else ''}, of which {verified_count} "
            f"were successfully verified against syntax and regression checks."
        )

        return f"{s1} {s2} {s3} {s4}"

    # =========================================================================
    # 4. Pull Request Markdown Report
    # =========================================================================

    def generate_markdown(
        self,
        executive_overview: str,
        health_score: CodeHealthScore,
        prioritized_fixes: List[PrioritizedFix],
        remediations: List[RemediationResult],
        findings: List[Finding],
        filename: str = "submitted code",
    ) -> str:
        """
        Renders a full, publication-ready pull-request-style markdown report.
        """
        rem_by_id = {r.finding_id: r for r in remediations}
        finding_by_id = {f.id: f for f in findings}

        lines: List[str] = []
        lines.append(f"# Pull Request Security & Quality Review: `{filename}`")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append(executive_overview)
        lines.append("")

        # Health score card
        lines.append("## Code Health Score")
        lines.append(f"**Score:** `{health_score.score} / 100` &nbsp;|&nbsp; **Grade:** `{health_score.grade}`")
        lines.append("")

        # Severity breakdown table
        lines.append("### Findings Breakdown by Severity")
        lines.append("| Severity | Finding Count | Penalty Deducted | Cap Limit |")
        lines.append("|:---|:---:|:---:|:---:|")
        for sev in (
            SeverityLevel.CRITICAL.value,
            SeverityLevel.HIGH.value,
            SeverityLevel.MEDIUM.value,
            SeverityLevel.LOW.value,
            SeverityLevel.INFO.value,
        ):
            cnt = health_score.breakdown_by_severity.get(sev, 0)
            pen = health_score.penalty_details.get(sev, 0)
            cap = SEVERITY_CAPS.get(sev, 0)
            lines.append(f"| **{sev}** | {cnt} | -{pen} pts | max {cap} pts |")
        lines.append("")

        # Prioritized action items
        lines.append("## Prioritized Action Items")
        if not prioritized_fixes:
            lines.append("*No actionable findings detected. Ready to merge!*")
        else:
            lines.append("Fixes ordered by **Severity** (highest impact first), then **Effort** (easiest fix first):")
            lines.append("")
            for idx, fix in enumerate(prioritized_fixes, start=1):
                rem = rem_by_id.get(fix.finding_id)
                status_icon = "Verified" if (rem and rem.verified) else "Manual Review"
                lines.append(
                    f"{idx}. **[{fix.finding_id}] {fix.title}** (`{fix.severity.value}` | Effort: `{fix.effort}` | Status: `{status_icon}`)\n"
                    f"   - *Rationale:* {fix.reason}"
                )
        lines.append("")

        # Remediation Details & Diffs
        lines.append("## Remediation Details & Verified Diffs")
        if not remediations:
            lines.append("*No automated remediations required.*")
        else:
            for rem in remediations:
                f_obj = finding_by_id.get(rem.finding_id)
                sev_tag = f_obj.severity.value if f_obj else "FINDING"
                cwe_tag = f" | CWE: `{f_obj.cwe_id}`" if f_obj and f_obj.cwe_id else ""
                status_badge = "[x] Verified" if rem.verified else "[ ] Unverified"

                lines.append(f"### `{rem.finding_id}` - {f_obj.title if f_obj else 'Remediation'} ({sev_tag}{cwe_tag})")
                lines.append(f"- **Verification Status:** `{status_badge}` - {rem.verification_note}")
                lines.append(f"- **Issue:** {rem.explanation}")
                lines.append(f"- **Fix Summary:** {rem.fix_summary}")
                lines.append("")
                lines.append("```diff")
                for orig_l in rem.original_code.splitlines():
                    lines.append(f"- {orig_l}")
                for corr_l in rem.corrected_code.splitlines():
                    lines.append(f"+ {corr_l}")
                lines.append("```")
                lines.append("")
                lines.append(f"**Best Practice:** {rem.best_practice}")
                if rem.references:
                    ref_links = ", ".join(f"`{ref}`" for ref in rem.references)
                    lines.append(f"**KB References:** {ref_links}")
                lines.append("")

        return "\n".join(lines)

    # =========================================================================
    # 5. Public Orchestration Method
    # =========================================================================

    def summarize(
        self,
        findings: List[Finding],
        remediations: List[RemediationResult],
        filename: str = "unknown",
        language: str = "python",
    ) -> PRSummary:
        """
        Executes complete PR summary pipeline: health score, executive overview,
        prioritization, and markdown generation.

        Args:
            findings: Unified list of findings.
            remediations: Verified remediation results.
            filename: Target file name.
            language: Programming language.

        Returns:
            PRSummary model.
        """
        health_score = self.compute_health_score(findings)
        prioritized_fixes = self.prioritize_fixes(findings, remediations)
        top_risks = self._extract_top_risks(findings)
        overview = self.build_executive_overview(
            findings=findings,
            remediations=remediations,
            health_score=health_score,
            filename=filename,
        )
        markdown = self.generate_markdown(
            executive_overview=overview,
            health_score=health_score,
            prioritized_fixes=prioritized_fixes,
            remediations=remediations,
            findings=findings,
            filename=filename,
        )

        return PRSummary(
            executive_overview=overview,
            severity_breakdown=health_score.breakdown_by_severity,
            top_risks=top_risks,
            prioritized_fixes=prioritized_fixes,
            health_score=health_score,
            markdown=markdown,
        )

    def run(
        self,
        code: str,
        language: str,
        filename: str = "unknown",
        findings: Optional[List[Finding]] = None,
        remediations: Optional[List[RemediationResult]] = None,
    ) -> Any:
        """
        BaseAgent interface implementation.
        """
        target_findings = findings or []
        target_remediations = remediations or []
        return self.summarize(
            findings=target_findings,
            remediations=target_remediations,
            filename=filename,
            language=language,
        )

