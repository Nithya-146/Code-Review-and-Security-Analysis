"""
Multi-Agent Orchestrator for AI Code Review & Security Analysis.

Coordinates parallel execution of CodeAnalysisAgent and SecurityAgent,
manages error isolation and timeouts, merges and deduplicates findings,
and produces a unified AnalysisResult.
"""

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
import logging
import time
from typing import Dict, List, Optional, Tuple

from agents.code_analysis import CodeAnalysisAgent
from agents.security import SecurityAgent
from app.schemas import AnalysisResult, Finding, SeverityLevel

logger = logging.getLogger(__name__)

# Configurable timeout in seconds for agent execution
DEFAULT_AGENT_TIMEOUT: float = 30.0

# Canonical ordering for severity levels
SEVERITY_WEIGHTS: Dict[str, int] = {
    SeverityLevel.CRITICAL.value: 5,
    SeverityLevel.HIGH.value: 4,
    SeverityLevel.MEDIUM.value: 3,
    SeverityLevel.LOW.value: 2,
    SeverityLevel.INFO.value: 1,
}


def _run_single_agent(
    agent_name: str,
    agent_instance: object,
    code: str,
    language: str,
    filename: str
) -> Tuple[str, List[Finding], float, Optional[str]]:
    """
    Executes a single agent with runtime benchmarking and error trapping.

    Args:
        agent_name: Descriptive name of the agent.
        agent_instance: Initialized BaseAgent instance.
        code: Source code string to inspect.
        language: Programming language ('python' or 'java').
        filename: Name of the file being reviewed.

    Returns:
        Tuple of (agent_name, findings_list, runtime_seconds, error_message_or_None).
    """
    start_time = time.perf_counter()
    try:
        run_fn = getattr(agent_instance, "run")
        findings = run_fn(code, language=language, filename=filename)
        duration = round(time.perf_counter() - start_time, 4)
        return (agent_name, findings, duration, None)
    except Exception as exc:
        duration = round(time.perf_counter() - start_time, 4)
        logger.exception("Agent '%s' failed during execution: %s", agent_name, exc)
        return (agent_name, [], duration, str(exc))


def _extract_finding_type(f: Finding) -> str:
    """Extracts normalized category/type for finding deduplication and evaluation."""
    if f.cwe_id:
        return f.cwe_id.strip().lower()
    if f.evidence and "Static AST Check: " in f.evidence:
        return f.evidence.split("Static AST Check: ")[-1].strip().lower()
    return f.title.strip().lower()


def _are_findings_overlapping(f1: Finding, f2: Finding) -> bool:
    """
    Checks if two findings share the same file, same category/type, and overlapping line ranges.
    """
    if f1.file != f2.file:
        return False

    type1 = _extract_finding_type(f1)
    type2 = _extract_finding_type(f2)
    same_type = (
        type1 == type2
        or f1.title.strip().lower() == f2.title.strip().lower()
        or (bool(f1.cwe_id) and f1.cwe_id == f2.cwe_id)
    )
    if not same_type:
        return False

    # Check for line span overlap: max(start1, start2) <= min(end1, end2)
    return max(f1.line_start, f2.line_start) <= min(f1.line_end, f2.line_end)


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """
    Deduplicates overlapping findings (same file, overlapping lines, same category),
    retaining the finding with the higher severity score and confidence.

    Args:
        findings: Raw combined list of findings.

    Returns:
        Deduplicated list of findings.
    """
    if not findings:
        return []

    deduped: List[Finding] = []
    for candidate in findings:
        subsumed = False
        for idx, existing in enumerate(deduped):
            if _are_findings_overlapping(candidate, existing):
                # Compare severity score, fallback to confidence
                cand_score = (candidate.severity_score, candidate.confidence)
                exist_score = (existing.severity_score, existing.confidence)
                if cand_score > exist_score:
                    # Candidate is higher severity; replace existing
                    deduped[idx] = candidate
                subsumed = True
                break
        if not subsumed:
            deduped.append(candidate)

    return deduped


def analyze(
    code: str,
    language: str,
    filename: str = "unknown",
    timeout: float = DEFAULT_AGENT_TIMEOUT,
    code_agent: Optional[CodeAnalysisAgent] = None,
    security_agent: Optional[SecurityAgent] = None
) -> AnalysisResult:
    """
    Executes parallel code quality and security vulnerability reviews.

    Args:
        code: Source code text to analyze.
        language: Programming language ('python' or 'java').
        filename: Name or relative path of the target file.
        timeout: Maximum seconds to wait per agent before timing out.
        code_agent: Optional pre-configured CodeAnalysisAgent instance.
        security_agent: Optional pre-configured SecurityAgent instance.

    Returns:
        AnalysisResult containing merged findings, metrics, and run status.
    """
    target_code_agent = code_agent or CodeAnalysisAgent(agent_name="code_analysis")
    target_sec_agent = security_agent or SecurityAgent(agent_name="security_analysis")

    agents_to_run = [
        ("code_analysis", target_code_agent),
        ("security_analysis", target_sec_agent),
    ]

    all_findings: List[Finding] = []
    run_status: Dict[str, str] = {}
    agent_runtimes: Dict[str, float] = {}

    with ThreadPoolExecutor(max_workers=len(agents_to_run)) as executor:
        future_map = {
            executor.submit(_run_single_agent, name, agent, code, language, filename): name
            for name, agent in agents_to_run
        }

        for future, name in future_map.items():
            try:
                agent_name, findings, duration, error = future.result(timeout=timeout)
                agent_runtimes[agent_name] = duration
                if error is not None:
                    run_status[agent_name] = f"ERROR: {error}"
                else:
                    run_status[agent_name] = "SUCCESS"
                    all_findings.extend(findings)
            except FutureTimeoutError:
                agent_runtimes[name] = timeout
                run_status[name] = f"TIMEOUT: Exceeded {timeout}s limit"
                logger.error("Agent '%s' timed out after %s seconds", name, timeout)
            except Exception as exc:
                agent_runtimes[name] = 0.0
                run_status[name] = f"ERROR: {exc}"
                logger.error("Unexpected error retrieving result from agent '%s': %s", name, exc)

    # 1. Deduplicate overlapping findings
    unique_findings = deduplicate_findings(all_findings)

    # 2. Sort by severity_score descending, then line_start ascending, then line_end
    unique_findings.sort(key=lambda f: (-f.severity_score, f.line_start, f.line_end))

    # 3. Compute counts by severity
    counts_by_severity: Dict[str, int] = {
        SeverityLevel.CRITICAL.value: 0,
        SeverityLevel.HIGH.value: 0,
        SeverityLevel.MEDIUM.value: 0,
        SeverityLevel.LOW.value: 0,
        SeverityLevel.INFO.value: 0,
    }
    for f in unique_findings:
        sev_key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        counts_by_severity[sev_key] = counts_by_severity.get(sev_key, 0) + 1

    # 4. Compute counts by agent
    counts_by_agent: Dict[str, int] = {
        "code_analysis": 0,
        "security_analysis": 0,
    }
    for f in unique_findings:
        agent_key = f.agent
        counts_by_agent[agent_key] = counts_by_agent.get(agent_key, 0) + 1

    return AnalysisResult(
        findings=unique_findings,
        counts_by_severity=counts_by_severity,
        counts_by_agent=counts_by_agent,
        per_agent_runtime=agent_runtimes,
        agent_runtimes=agent_runtimes,
        language=language,
        filename=filename,
        run_status=run_status,
    )
