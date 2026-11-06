"""
RAG-Powered Conversational Code Review & Security Assistant.

Provides the ChatAssistant class which answers user questions about code quality,
security vulnerabilities, remediations, and general secure coding concepts.
Integrates rule-based intent classification, finding resolution, ChromaDB vector
retrieval, grounding verification, and conversation history tracking.
"""

from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from app.schemas import (
    AnalysisResult,
    ChatMessage,
    ChatResponse,
    Citation,
    Finding,
    RemediationResult,
    SeverityLevel,
)

logger = logging.getLogger(__name__)

# Minimum cosine similarity threshold to consider a retrieved chunk grounded
MIN_RELEVANCE_THRESHOLD: float = 0.25

# Standard out-of-scope keywords
OUT_OF_SCOPE_WORDS: Set[str] = {
    "weather", "forecast", "rain", "temperature", "climate",
    "sports", "football", "baseball", "basketball", "cricket", "soccer",
    "movie", "cinema", "actor", "recipe", "cook", "pasta", "pizza",
    "president", "election", "politics", "capital of",
    "joke", "poem", "sing", "song", "lyrics", "horoscope",
    "stock price", "crypto price", "bitcoin", "solana",
}

# Domain keywords to check if an unclassified question is in-scope
IN_SCOPE_DOMAIN_WORDS: Set[str] = {
    "code", "line", "function", "class", "file", "method", "variable",
    "security", "vulnerability", "cwe", "owasp", "defect", "smell", "bug",
    "sql", "sqli", "injection", "xss", "csrf", "secret", "password", "key",
    "token", "crypto", "hash", "md5", "sha", "deserialization", "pickle",
    "command", "shell", "traversal", "path", "ssrf", "exception", "catch",
    "except", "magic", "nesting", "complexity", "health", "score", "fix",
    "remediation", "patch", "review", "audit", "python", "java",
}


def _detect_intent(question: str) -> str:
    """
    Classifies the user's question into one of the canonical intent categories:
    - finding_explanation
    - fix_request
    - concept_question
    - best_practice
    - summary_request
    - out_of_scope
    """
    q_lower = question.lower().strip()
    words = set(re.findall(r"\b[a-z]+\b", q_lower))

    # 1. Out-of-scope keyword detection
    if words.intersection(OUT_OF_SCOPE_WORDS):
        return "out_of_scope"

    # 2. Summary Request Patterns
    summary_patterns = [
        r"\b(fix first|prioritize|top risks?|health score|overall health|grade)\b",
        r"\b(summary|overview|summarize|what findings?|what issues?|list findings?)\b",
        r"\b(what should (i|we) (fix|do) first)\b",
    ]
    if any(re.search(pat, q_lower) for pat in summary_patterns):
        return "summary_request"

    # 3. Fix Request Patterns
    fix_patterns = [
        r"\b(how (do|can|should) (i|we) (fix|resolve|remediate|patch|address|solve))\b",
        r"\b(how to (fix|resolve|remediate|patch|address|solve))\b",
        r"\b(show (me )?(the )?(fix|solution|corrected code|patch|replacement))\b",
        r"\b(fix (finding|issue|vulnerability|line|it|this|that))\b",
        r"\b(give (me )?(the )?code (fix|to fix))\b",
        r"\b(can you fix)\b",
        r"\b(how do i fix)\b",
        r"\b(how to fix finding)\b",
    ]
    if any(re.search(pat, q_lower) for pat in fix_patterns):
        return "fix_request"

    # 4. Finding Explanation Patterns
    explanation_patterns = [
        r"\b(why is line \d+ flagged|why is finding \w+ flagged|why was line \d+ flagged)\b",
        r"\b(why is (finding|line|this|that|it) (an? )?(issue|problem|flagged|bad|dangerous|vulnerability))\b",
        r"\b(what is wrong with (line \d+|finding|this|that))\b",
        r"\b(explain (finding|line \d+|this finding|that finding|the finding))\b",
        r"\b(why did you flag)\b",
        r"\b(tell me about (finding|line \d+))\b",
        r"\b(details on (finding|line \d+))\b",
        r"\b(why is line \d+)\b",
    ]
    if any(re.search(pat, q_lower) for pat in explanation_patterns):
        return "finding_explanation"

    # 5. Best Practice Patterns
    best_practice_patterns = [
        r"\b(best practices?|recommended way|industry standard|proper way to|guidelines for|secure way to)\b",
        r"\b(how should (i|we) (properly|securely) (handle|store|sanitize|implement))\b",
    ]
    if any(re.search(pat, q_lower) for pat in best_practice_patterns):
        return "best_practice"

    # 6. Concept Question Patterns
    concept_patterns = [
        r"\b(what is|what are|explain|how does)\s+(csrf|xss|sqli|sql injection|cwe-\d+|owasp|command injection|path traversal|deserialization|ssrf|broken access control|cryptographic failure|taint analysis|shannon entropy)\b",
        r"\b(what does \w+ mean)\b",
        r"\b(define \w+)\b",
        r"\b(what is csrf|what is xss|what is sql injection|what is cwe)\b",
    ]
    if any(re.search(pat, q_lower) for pat in concept_patterns):
        return "concept_question"

    # 7. Fallback classification: check if domain keywords exist
    if not words.intersection(IN_SCOPE_DOMAIN_WORDS):
        return "out_of_scope"

    # If domain keywords are present but no specific intent was matched:
    if "fix" in words or "patch" in words:
        return "fix_request"
    if "why" in words or "explain" in words:
        return "finding_explanation"
    if "what" in words:
        return "concept_question"

    return "finding_explanation"


def _extract_last_finding_from_history(history: List[ChatMessage], findings_by_id: Dict[str, Finding]) -> Optional[Finding]:
    """
    Inspects recent conversation messages to identify the most recently discussed finding.
    """
    if not history:
        return None

    # Scan from newest to oldest
    for msg in reversed(history):
        content = msg.content
        # Check for direct ID matches
        for fid, f in findings_by_id.items():
            if fid.lower() in content.lower():
                return f
        # Check for "finding N" in message
        match = re.search(r"\bfinding\s*#?\s*(\d+)\b", content, re.IGNORECASE)
        if match:
            idx = int(match.group(1)) - 1
            f_list = list(findings_by_id.values())
            if 0 <= idx < len(f_list):
                return f_list[idx]
        # Check for vulnerability keywords in message
        for f in findings_by_id.values():
            if f.title.lower() in content.lower():
                return f

    return None


class ChatAssistant:
    """
    RAG-powered conversational assistant for exploring code review findings,
    explaining vulnerabilities, generating actionable remediations, and answering
    secure coding inquiries with citations to ChromaDB knowledge sources.
    """

    def __init__(
        self,
        analysis_result: AnalysisResult,
        code: str,
        language: str,
        retriever: Optional[Any] = None,
    ) -> None:
        """
        Initializes the assistant with analysis results, source code, and knowledge base retriever.

        Args:
            analysis_result: Result object containing findings and remediations from orchestrator.
            code: Target source code text.
            language: Programming language ('python' or 'java').
            retriever: Optional pre-configured Retriever instance for KB queries.
        """
        self.analysis_result = analysis_result
        self.code = code
        self.language = (language or "python").strip().lower()
        self.retriever = retriever
        if self.retriever is None:
            self._init_retriever()

        # Fast lookup maps
        self.findings_by_id: Dict[str, Finding] = {f.id: f for f in self.analysis_result.findings}
        self.remediations_by_id: Dict[str, RemediationResult] = {
            r.finding_id: r for r in self.analysis_result.remediations
        }

    def _init_retriever(self) -> None:
        """Attaches to process-level shared Retriever singleton; handles offline fallback."""
        try:
            from kb.retriever import retriever_singleton
            self.retriever = retriever_singleton()
        except Exception as err:
            logger.warning("Retriever unavailable for ChatAssistant: %s. Continuing offline.", err)
            self.retriever = None

    # =========================================================================
    # 1. Finding Resolution
    # =========================================================================

    def resolve_finding(
        self,
        question: str,
        history: Optional[List[ChatMessage]] = None,
    ) -> Tuple[Optional[Finding], Optional[str]]:
        """
        Resolves finding references in user question to an actual Finding object:
        - By ordinal or number ("finding 2", "second finding", "finding #1")
        - By line number ("line 14", "at line 18")
        - By vulnerability name or CWE ("the SQL injection", "hardcoded secret", "CWE-89")
        - By anaphora ("that one", "this issue", "it") using conversation history

        Returns:
            Tuple of (Finding or None, error_status_or_None).
        """
        q_lower = question.lower()
        findings = self.analysis_result.findings

        # 1. Direct Finding ID match
        for f in findings:
            if f.id.lower() in q_lower:
                return (f, None)

        # 2. Number or Ordinal Match ("finding 2", "finding #2", "2nd finding")
        num_match = re.search(r"\bfinding\s*#?\s*(\d+)\b", q_lower)
        if num_match:
            idx = int(num_match.group(1)) - 1
            if 0 <= idx < len(findings):
                return (findings[idx], None)
            else:
                return (None, f"Finding #{num_match.group(1)} does not exist. Total findings: {len(findings)}.")

        # Ordinals
        ordinals = {"first": 0, "1st": 0, "second": 1, "2nd": 1, "third": 2, "3rd": 2, "fourth": 3, "4th": 3, "fifth": 4, "5th": 4}
        for ord_word, idx in ordinals.items():
            if re.search(rf"\b{ord_word}\s+finding\b", q_lower):
                if 0 <= idx < len(findings):
                    return (findings[idx], None)
                else:
                    return (None, f"The {ord_word} finding is out of range.")

        # 3. Line Number Match ("line 14", "at line 18")
        line_match = re.search(r"\bline\s*(\d+)\b", q_lower)
        if line_match:
            line_no = int(line_match.group(1))
            # Find finding spanning this line or starting on this line
            for f in findings:
                if f.line_start <= line_no <= f.line_end:
                    return (f, None)
            # Closest start line within 2 lines
            closest = None
            min_dist = 999
            for f in findings:
                dist = abs(f.line_start - line_no)
                if dist <= 2 and dist < min_dist:
                    min_dist = dist
                    closest = f
            if closest:
                return (closest, None)

        # 4. Anaphora / History Resolution ("that one", "this issue", "it", "that finding")
        anaphoric_pattern = re.compile(r"\b(that one|this one|it|this issue|that issue|this finding|that finding|the same issue)\b")
        if anaphoric_pattern.search(q_lower) and history:
            last_finding = _extract_last_finding_from_history(history, self.findings_by_id)
            if last_finding:
                return (last_finding, None)

        # 5. Vulnerability / Smell Name Match
        vuln_keywords = [
            ("sql injection", ["sql", "sqli", "cwe-89"]),
            ("hardcoded secret", ["secret", "api key", "password", "token", "cwe-798"]),
            ("command injection", ["command injection", "os.system", "cwe-78"]),
            ("cross-site scripting", ["xss", "cross-site scripting", "cwe-79"]),
            ("insecure deserialization", ["deserialization", "pickle", "cwe-502"]),
            ("weak cryptography", ["weak hash", "md5", "sha-1", "crypto", "cwe-327", "cwe-328"]),
            ("bare except", ["bare except", "except:", "broad exception"]),
            ("magic number", ["magic number", "magic literal"]),
        ]
        for canonical, kw_list in vuln_keywords:
            if any(kw in q_lower for kw in kw_list):
                for f in findings:
                    f_text = f"{f.title} {f.cwe_id or ''} {f.explanation}".lower()
                    if any(kw in f_text for kw in kw_list):
                        return (f, None)

        # If question has history and asks a generic question (e.g. "how do i fix it?"):
        if history:
            last_finding = _extract_last_finding_from_history(history, self.findings_by_id)
            if last_finding:
                return (last_finding, None)

        return (None, None)

    # =========================================================================
    # 2. Context-Aware Knowledge Base Retrieval
    # =========================================================================

    def _retrieve_kb_context(
        self,
        question: str,
        finding: Optional[Finding] = None,
        k: int = 3,
    ) -> List[Citation]:
        """
        Retrieves relevant chunks from ChromaDB knowledge base based on the question
        and finding details, filtering out chunks below the relevance threshold.
        """
        if self.retriever is None:
            return []

        # Construct retrieval query
        if finding:
            cwe_tag = finding.cwe_id or ""
            retrieval_query = f"{finding.title} {cwe_tag} {finding.explanation} {question}"
        else:
            retrieval_query = question

        try:
            hits = self.retriever.search(query=retrieval_query, k=k)
        except Exception as exc:
            logger.warning("Knowledge base retrieval failed: %s", exc)
            return []

        citations: List[Citation] = []
        for h in hits:
            score = float(h.get("similarity_score", 0.0))
            if score >= MIN_RELEVANCE_THRESHOLD:
                text_snippet = h.get("text", "").strip()
                if len(text_snippet) > 220:
                    text_snippet = text_snippet[:220].rstrip() + "..."
                citations.append(
                    Citation(
                        source=h.get("source", "knowledge_base"),
                        section=h.get("category", "GENERAL"),
                        chunk_id=h.get("source", "chunk"),
                        snippet=text_snippet,
                        relevance_score=score,
                    )
                )

        return citations

    # =========================================================================
    # 3. Follow-up Suggestions Generator
    # =========================================================================

    def _generate_follow_up_suggestions(
        self,
        intent: str,
        finding: Optional[Finding] = None,
    ) -> List[str]:
        """
        Generates 2-3 contextual follow-up questions tailored to intent and finding.
        """
        if intent == "out_of_scope":
            return [
                "What are the top security risks in this file?",
                "How do I fix the highest severity finding?",
                "What is the code health score?",
            ]

        if intent == "summary_request":
            return [
                "How do I fix the highest priority finding?",
                "What is the most critical security risk?",
                "Can you explain why the health score was deducted?",
            ]

        if finding:
            fid = finding.id
            line = finding.line_start
            if intent == "finding_explanation":
                return [
                    f"How do I fix finding {fid}?",
                    f"Show me the safe replacement code for line {line}.",
                    "What is the industry best practice to prevent this?",
                ]
            elif intent == "fix_request":
                return [
                    f"Why is this fix safer than the original code?",
                    f"How can I test finding {fid} after applying the fix?",
                    "What other security findings are present in this file?",
                ]
            else:
                return [
                    f"How does finding {fid} impact overall code health?",
                    f"Show me the recommended fix for finding {fid}.",
                    "What are related OWASP Top 10 guidelines?",
                ]

        # General concept or best practice
        return [
            "Are there any findings related to this in my code?",
            "What is the best practice for secure implementation?",
            "What should I prioritize fixing first?",
        ]

    # =========================================================================
    # 4. Answer Composition Engines by Intent
    # =========================================================================

    def _answer_out_of_scope(self, question: str) -> ChatResponse:
        """Handles non-code review or non-security questions with a polite redirect."""
        answer = (
            "I am an AI Code Review and Security Analysis Assistant specialized in code quality, "
            "vulnerabilities (OWASP Top 10, CWE), automated remediations, and code health scoring.\n\n"
            "Your question appears to be outside this domain. Please ask about code quality findings, "
            "security flaws in your code, remediation fixes, or secure coding best practices."
        )
        return ChatResponse(
            answer=answer,
            citations=[],
            related_finding_ids=[],
            grounded=False,
            follow_up_suggestions=self._generate_follow_up_suggestions("out_of_scope"),
            intent="out_of_scope",
        )

    def _answer_summary(self, question: str, citations: List[Citation]) -> ChatResponse:
        """Composes response for summary or prioritization questions."""
        hs = self.analysis_result.health_score
        pr = self.analysis_result.pr_summary
        findings = self.analysis_result.findings

        lines: List[str] = []
        if hs:
            lines.append(f"### Code Review & Health Summary (Score: {hs.score}/100, Grade: {hs.grade})")
        else:
            lines.append("### Code Review Summary")

        if pr and pr.executive_overview:
            lines.append(f"\n{pr.executive_overview}\n")

        if not findings:
            lines.append("No security vulnerabilities or code smells were detected in the analyzed code.")
        else:
            lines.append("#### Priority Action Items (What to Fix First):")
            if pr and pr.prioritized_fixes:
                for idx, fix in enumerate(pr.prioritized_fixes[:3], start=1):
                    lines.append(
                        f"{idx}. **[{fix.finding_id}] {fix.title}** ({fix.severity.value} | Effort: {fix.effort})\n"
                        f"   - *Rationale:* {fix.reason}"
                    )
            else:
                for idx, f in enumerate(findings[:3], start=1):
                    lines.append(f"{idx}. **[{f.id}] {f.title}** ({f.severity.value} at line {f.line_start})")

            # Severity counts breakdown
            sev_counts = self.analysis_result.counts_by_severity
            lines.append("\n**Findings Breakdown:** " + ", ".join(f"{k}: {v}" for k, v in sev_counts.items() if v > 0))

        answer = "\n".join(lines)
        related_ids = [f.id for f in findings[:3]]

        return ChatResponse(
            answer=answer,
            citations=citations,
            related_finding_ids=related_ids,
            grounded=len(citations) > 0,
            follow_up_suggestions=self._generate_follow_up_suggestions("summary_request"),
            intent="summary_request",
        )

    def _answer_finding_explanation(
        self,
        finding: Optional[Finding],
        error_msg: Optional[str],
        citations: List[Citation],
    ) -> ChatResponse:
        """Composes detailed explanation for why a specific finding was flagged."""
        if error_msg or not finding:
            msg = error_msg or (
                "Could not identify the specific finding you referenced. "
                f"The analyzed file contains {len(self.analysis_result.findings)} finding(s). "
                "You can specify a finding by number (e.g., 'finding 1'), line (e.g., 'line 14'), or vulnerability name."
            )
            return ChatResponse(
                answer=msg,
                citations=[],
                related_finding_ids=[],
                grounded=False,
                follow_up_suggestions=self._generate_follow_up_suggestions("summary_request"),
                intent="finding_explanation",
            )

        lines: List[str] = []
        cwe_part = f" | CWE: {finding.cwe_id}" if finding.cwe_id else ""
        lines.append(f"### Finding [{finding.id}]: {finding.title} ({finding.severity.value}{cwe_part})")
        lines.append(f"\n**Location:** Line {finding.line_start} to {finding.line_end} in `{self.analysis_result.filename}`")

        # Short answer
        lines.append(f"\n**Why It Is Flagged:**\n{finding.explanation}")

        # Code snippet
        if finding.code_snippet:
            lines.append(f"\n**Flagged Code Snippet:**\n```{self.language}\n{finding.code_snippet}\n```")

        # Knowledge Base guidance
        if citations:
            lines.append("\n**Security Knowledge Base Guidance:**")
            lines.append(citations[0].snippet)
        else:
            lines.append("\n*Note: The knowledge base does not contain an exact text chunk matching this finding; explanation is derived from static rule analysis.*")

        # Actionable suggestion
        if finding.suggestion:
            lines.append(f"\n**Recommendation:** {finding.suggestion}")

        answer = "\n".join(lines)
        return ChatResponse(
            answer=answer,
            citations=citations,
            related_finding_ids=[finding.id],
            grounded=len(citations) > 0,
            follow_up_suggestions=self._generate_follow_up_suggestions("finding_explanation", finding),
            intent="finding_explanation",
        )

    def _answer_fix_request(
        self,
        finding: Optional[Finding],
        error_msg: Optional[str],
        citations: List[Citation],
    ) -> ChatResponse:
        """Composes code remediation response with diff and verification status."""
        if error_msg or not finding:
            msg = error_msg or (
                "Please specify which finding or line number you would like to remediate "
                "(e.g., 'how to fix finding 1' or 'how do I fix line 14?')."
            )
            return ChatResponse(
                answer=msg,
                citations=[],
                related_finding_ids=[],
                grounded=False,
                follow_up_suggestions=self._generate_follow_up_suggestions("summary_request"),
                intent="fix_request",
            )

        rem = self.remediations_by_id.get(finding.id)
        lines: List[str] = []
        lines.append(f"### Recommended Fix for [{finding.id}]: {finding.title}")

        if rem:
            lines.append(f"\n**Fix Summary:** {rem.fix_summary}")
            lines.append(f"\n**Verification Status:** {'[x] Verified' if rem.verified else '[ ] Unverified'} ({rem.verification_note})")

            # Before / After Diff
            lines.append("\n**Code Diff (Before vs. After):**")
            lines.append("```diff")
            for orig_line in rem.original_code.splitlines():
                lines.append(f"- {orig_line}")
            for corr_line in rem.corrected_code.splitlines():
                lines.append(f"+ {corr_line}")
            lines.append("```")

            lines.append(f"\n**Best Practice:** {rem.best_practice}")
        else:
            lines.append(f"\n**Recommendation:** {finding.suggestion or 'Refactor to follow secure coding standards.'}")
            if finding.code_snippet:
                lines.append(f"\n**Original Code:**\n```{self.language}\n{finding.code_snippet}\n```")

        if citations:
            lines.append(f"\n**Knowledge Base Reference ({citations[0].source}):**")
            lines.append(citations[0].snippet)

        answer = "\n".join(lines)
        return ChatResponse(
            answer=answer,
            citations=citations,
            related_finding_ids=[finding.id],
            grounded=len(citations) > 0,
            follow_up_suggestions=self._generate_follow_up_suggestions("fix_request", finding),
            intent="fix_request",
        )

    def _answer_concept_or_practice(
        self,
        question: str,
        intent: str,
        citations: List[Citation],
        finding: Optional[Finding] = None,
    ) -> ChatResponse:
        """Answers general security concept or best practice questions using retrieved KB facts."""
        related_ids = [finding.id] if finding else []

        if not citations:
            answer = (
                f"The knowledge base does not contain specific documentation matching '{question}'. "
                "Please consult official OWASP Top 10:2025 guidelines or ask about a specific vulnerability "
                "such as SQL injection, broken access control, hardcoded secrets, or cryptographic failures."
            )
            return ChatResponse(
                answer=answer,
                citations=[],
                related_finding_ids=related_ids,
                grounded=False,
                follow_up_suggestions=self._generate_follow_up_suggestions(intent, finding),
                intent=intent,
            )

        top_citation = citations[0]
        lines: List[str] = []
        topic_header = "Security Concept" if intent == "concept_question" else "Secure Coding Best Practice"
        lines.append(f"### {topic_header}: {top_citation.source.replace('.md', '').replace('_', ' ').title()}")
        lines.append(f"\n**Knowledge Base Guidance:**\n{top_citation.snippet}")

        if len(citations) > 1:
            lines.append(f"\n**Additional Context ({citations[1].source}):**\n{citations[1].snippet}")

        if finding:
            lines.append(f"\n*Note: This concept relates directly to finding [{finding.id}] ({finding.title}) at line {finding.line_start} in your code.*")

        answer = "\n".join(lines)
        return ChatResponse(
            answer=answer,
            citations=citations,
            related_finding_ids=related_ids,
            grounded=True,
            follow_up_suggestions=self._generate_follow_up_suggestions(intent, finding),
            intent=intent,
        )

    # =========================================================================
    # 5. Main Entrypoint: ask()
    # =========================================================================

    def ask(
        self,
        question: str,
        history: Optional[List[ChatMessage]] = None,
    ) -> ChatResponse:
        """
        Executes the conversational assistant pipeline for a user question:
        1. Validates and sanitizes input.
        2. Detects user intent (rule-based).
        3. Resolves finding references (by ID, number, line, vulnerability, or history).
        4. Retrieves contextual facts from ChromaDB knowledge base.
        5. Enforces grounding verification and builds structured response with citations.
        6. Generates tailored follow-up suggestions.

        Args:
            question: User inquiry string.
            history: Optional list of previous ChatMessage turns.

        Returns:
            ChatResponse object containing answer, citations, related findings, and suggestions.
        """
        # 1. Edge Case: Empty or whitespace query
        if not question or not question.strip():
            return ChatResponse(
                answer="Please enter a question regarding your code review results or security guidelines.",
                citations=[],
                related_finding_ids=[],
                grounded=False,
                follow_up_suggestions=self._generate_follow_up_suggestions("summary_request"),
                intent="summary_request",
            )

        clean_question = question.strip()[:1500]
        history_list = history or []

        # 2. Intent Detection
        intent = _detect_intent(clean_question)

        # 3. Early exit for out of scope
        if intent == "out_of_scope":
            return self._answer_out_of_scope(clean_question)

        # 4. Finding Resolution
        resolved_finding, resolution_error = self.resolve_finding(clean_question, history=history_list)

        # 5. Context-Aware Retrieval
        citations = self._retrieve_kb_context(clean_question, finding=resolved_finding, k=3)

        # 6. Synthesize Response by Intent
        if intent == "summary_request":
            return self._answer_summary(clean_question, citations)

        elif intent == "finding_explanation":
            return self._answer_finding_explanation(resolved_finding, resolution_error, citations)

        elif intent == "fix_request":
            return self._answer_fix_request(resolved_finding, resolution_error, citations)

        elif intent in ("concept_question", "best_practice"):
            return self._answer_concept_or_practice(clean_question, intent, citations, finding=resolved_finding)

        # Fallback to explanation
        return self._answer_finding_explanation(resolved_finding, resolution_error, citations)

