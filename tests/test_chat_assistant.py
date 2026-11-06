"""
Unit and Integration Tests for RAG-powered Conversational Code Assistant (Milestone 3 Step 2).

Verifies:
1. Intent classification for each intent type:
   - finding_explanation
   - fix_request
   - concept_question
   - best_practice
   - summary_request
   - out_of_scope
2. Finding resolution:
   - by number ("finding 2")
   - by line ("line 14")
   - by vulnerability name ("the SQL injection")
   - by anaphora / history ("that one")
3. Concept question grounding (grounded=True, citations present)
4. Out-of-scope redirection (grounded=False, polite redirect)
5. Fix request integration with RemediationResult (before/after code diff)
6. Follow-up resolution with conversation history
7. Edge cases (empty question, no findings, out-of-bounds finding number, long query)
8. End-to-end execution on Python and Java sample files using orchestrator and real ChromaDB KB
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import pytest

from agents.chat_assistant import ChatAssistant, _detect_intent
from agents.orchestrator import analyze, create_chat_assistant
from app.schemas import (
    AnalysisResult,
    ChatMessage,
    ChatResponse,
    Citation,
    Finding,
    RemediationResult,
    SeverityLevel,
)
from kb.retriever import retriever_singleton

SAMPLE_DIR = Path(__file__).resolve().parent / "samples"


class MockRetriever:
    """Fast mock retriever for isolated unit tests without model overhead."""

    def search(self, query: str, k: int = 3, category: Optional[str] = None) -> List[Dict[str, Any]]:
        q = query.lower()
        if any(w in q for w in ("weather", "sports", "cook", "pasta")):
            return []
        if any(w in q for w in ("sql", "injection", "cwe-89", "query")):
            return [
                {
                    "text": "SQL injection occurs when untrusted input is concatenated into query strings. Use parameterized queries.",
                    "source": "A05_injection.md",
                    "category": "A05",
                    "similarity_score": 0.88,
                }
            ]
        if any(w in q for w in ("secret", "api_key", "password", "cwe-798")):
            return [
                {
                    "text": "Never hardcode secrets in source code. Retrieve sensitive credentials from environment variables.",
                    "source": "A07_authentication_failures.md",
                    "category": "A07",
                    "similarity_score": 0.82,
                }
            ]
        return [
            {
                "text": "General OWASP secure coding guidance recommendations.",
                "source": "A06_insecure_design.md",
                "category": "A06",
                "similarity_score": 0.65,
            }
        ]


def _build_test_analysis_result() -> AnalysisResult:
    """Builds a test AnalysisResult with sample findings and remediations."""
    f1 = Finding(
        id="SEC-001",
        title="SQL Injection",
        category="Security Vulnerability",
        agent="security_analysis",
        severity=SeverityLevel.CRITICAL,
        severity_score=9.8,
        file="app.py",
        line_start=18,
        line_end=19,
        code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        explanation="Dynamic SQL query execution via f-string.",
        suggestion="Use parameterized queries with ? placeholders.",
        confidence=0.95,
        cwe_id="CWE-89",
    )
    f2 = Finding(
        id="SEC-002",
        title="Hardcoded Secret",
        category="Security Vulnerability",
        agent="security_analysis",
        severity=SeverityLevel.HIGH,
        severity_score=8.5,
        file="app.py",
        line_start=12,
        line_end=12,
        code_snippet='API_KEY = "AKIAIOSFODNN7EXAMPLE12345"',
        explanation="Hardcoded AWS credential key in source code.",
        suggestion="Load credential via os.environ.get.",
        confidence=0.90,
        cwe_id="CWE-798",
    )
    f3 = Finding(
        id="QLT-001",
        title="Bare Except Clause",
        category="Code Smell",
        agent="code_analysis",
        severity=SeverityLevel.MEDIUM,
        severity_score=5.0,
        file="app.py",
        line_start=35,
        line_end=37,
        code_snippet="except:\n    pass",
        explanation="Bare except clause catches SystemExit and KeyboardInterrupt.",
        suggestion="Catch specific domain exceptions.",
        confidence=0.85,
    )

    rem1 = RemediationResult(
        finding_id="SEC-001",
        explanation="Dynamic SQL construction allows query manipulation.",
        fix_summary="Replace f-string query with parameterized cursor.execute call.",
        original_code="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        corrected_code="cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        best_practice="Always use parameterized queries or an ORM with parameter binding.",
        references=["A05_injection.md"],
        verified=True,
        verification_note="Verified: Syntax check passed and finding eliminated.",
        confidence=0.95,
    )
    rem2 = RemediationResult(
        finding_id="SEC-002",
        explanation="Plaintext secrets in source code lead to exposure.",
        fix_summary="Load API key from environment variable.",
        original_code='API_KEY = "AKIAIOSFODNN7EXAMPLE12345"',
        corrected_code='API_KEY = os.environ.get("API_KEY", "")',
        best_practice="Store secrets in environment variables or vaults.",
        references=["A07_authentication_failures.md"],
        verified=True,
        verification_note="Verified: Syntax check passed.",
        confidence=0.90,
    )

    return AnalysisResult(
        findings=[f1, f2, f3],
        counts_by_severity={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "INFO": 0},
        counts_by_agent={"security_analysis": 2, "code_analysis": 1},
        language="python",
        filename="app.py",
        remediations=[rem1, rem2],
    )


# =============================================================================
# 1. Intent Classification Tests
# =============================================================================

def test_intent_classification_all_types():
    """Verifies that rule-based intent detection accurately classifies all intent categories."""
    # finding_explanation
    assert _detect_intent("Why is line 14 flagged?") == "finding_explanation"
    assert _detect_intent("Explain finding 2") == "finding_explanation"
    assert _detect_intent("What is wrong with line 18?") == "finding_explanation"
    assert _detect_intent("Why did you flag this finding?") == "finding_explanation"

    # fix_request
    assert _detect_intent("How do I fix finding 3?") == "fix_request"
    assert _detect_intent("How to fix the SQL injection?") == "fix_request"
    assert _detect_intent("Show me the fix for line 12") == "fix_request"
    assert _detect_intent("Can you fix finding 1?") == "fix_request"

    # concept_question
    assert _detect_intent("What is CSRF?") == "concept_question"
    assert _detect_intent("Explain CWE-89") == "concept_question"
    assert _detect_intent("What is SQL injection?") == "concept_question"
    assert _detect_intent("How does command injection work?") == "concept_question"

    # best_practice
    assert _detect_intent("What is the best practice for storing passwords?") == "best_practice"
    assert _detect_intent("What is the recommended way to handle exceptions?") == "best_practice"
    assert _detect_intent("Guidelines for secure cookie storage") == "best_practice"

    # summary_request
    assert _detect_intent("What should I fix first?") == "summary_request"
    assert _detect_intent("Summarize the findings in this file") == "summary_request"
    assert _detect_intent("What are the top risks?") == "summary_request"
    assert _detect_intent("What is my code health score?") == "summary_request"

    # out_of_scope
    assert _detect_intent("What is the weather in Paris?") == "out_of_scope"
    assert _detect_intent("Who won the football game?") == "out_of_scope"
    assert _detect_intent("Write me a poem about spring") == "out_of_scope"
    assert _detect_intent("Can you give me a recipe for chocolate cake?") == "out_of_scope"


# =============================================================================
# 2. Finding Resolution Tests
# =============================================================================

def test_resolve_finding_by_number():
    """Verifies finding resolution by index or ordinal ('finding 2', 'first finding')."""
    res = _build_test_analysis_result()
    assistant = ChatAssistant(analysis_result=res, code="", language="python", retriever=MockRetriever())

    f, err = assistant.resolve_finding("What is wrong with finding 2?")
    assert err is None
    assert f is not None
    assert f.id == "SEC-002"

    f_first, _ = assistant.resolve_finding("Explain the first finding")
    assert f_first is not None
    assert f_first.id == "SEC-001"


def test_resolve_finding_by_line():
    """Verifies finding resolution by source line number ('line 18')."""
    res = _build_test_analysis_result()
    assistant = ChatAssistant(analysis_result=res, code="", language="python", retriever=MockRetriever())

    f, err = assistant.resolve_finding("Why is line 18 flagged?")
    assert err is None
    assert f is not None
    assert f.id == "SEC-001"


def test_resolve_finding_by_vulnerability_name():
    """Verifies finding resolution by vulnerability title or keyword."""
    res = _build_test_analysis_result()
    assistant = ChatAssistant(analysis_result=res, code="", language="python", retriever=MockRetriever())

    f_sql, _ = assistant.resolve_finding("How do I fix the SQL injection?")
    assert f_sql is not None
    assert f_sql.id == "SEC-001"

    f_sec, _ = assistant.resolve_finding("Tell me about the hardcoded secret")
    assert f_sec is not None
    assert f_sec.id == "SEC-002"


def test_resolve_finding_by_anaphora_history():
    """Verifies resolution of 'that one' or 'this issue' using conversation history."""
    res = _build_test_analysis_result()
    assistant = ChatAssistant(analysis_result=res, code="", language="python", retriever=MockRetriever())

    history = [
        ChatMessage(role="user", content="Why is finding 2 flagged?", timestamp=None),
        ChatMessage(role="assistant", content="Finding SEC-002 is a hardcoded secret...", timestamp=None),
    ]

    f, err = assistant.resolve_finding("How do I fix that one?", history=history)
    assert err is None
    assert f is not None
    assert f.id == "SEC-002"


# =============================================================================
# 3. Grounding & Citations Tests
# =============================================================================

def test_concept_question_grounded_with_citation():
    """Verifies that a concept question returns grounded=True with at least one citation."""
    res = _build_test_analysis_result()
    assistant = ChatAssistant(analysis_result=res, code="", language="python", retriever=MockRetriever())

    response: ChatResponse = assistant.ask("What is SQL injection?")

    assert response.intent == "concept_question"
    assert response.grounded is True
    assert len(response.citations) >= 1
    assert "A05_injection.md" in response.citations[0].source
    assert response.citations[0].relevance_score > 0.0
    assert len(response.follow_up_suggestions) >= 2


def test_out_of_scope_redirect():
    """Verifies that an out-of-scope question is politely redirected with grounded=False."""
    res = _build_test_analysis_result()
    assistant = ChatAssistant(analysis_result=res, code="", language="python", retriever=MockRetriever())

    response: ChatResponse = assistant.ask("What's the weather today in New York?")

    assert response.intent == "out_of_scope"
    assert response.grounded is False
    assert len(response.citations) == 0
    assert "outside" in response.answer.lower() or "scope" in response.answer.lower()
    assert len(response.follow_up_suggestions) >= 2


# =============================================================================
# 4. Fix Request & History Tests
# =============================================================================

def test_fix_request_includes_corrected_code():
    """Verifies that a fix request presents before/after code diff from RemediationResult."""
    res = _build_test_analysis_result()
    assistant = ChatAssistant(analysis_result=res, code="", language="python", retriever=MockRetriever())

    response: ChatResponse = assistant.ask("How do I fix finding 1?")

    assert response.intent == "fix_request"
    assert "SEC-001" in response.related_finding_ids
    assert "```diff" in response.answer
    assert "- cursor.execute" in response.answer
    assert "+ cursor.execute" in response.answer
    assert "Verified" in response.answer


def test_follow_up_using_history():
    """Verifies follow-up query resolution using previous chat context."""
    res = _build_test_analysis_result()
    assistant = ChatAssistant(analysis_result=res, code="", language="python", retriever=MockRetriever())

    history = [
        ChatMessage(role="user", content="Explain finding 1", timestamp=None),
        ChatMessage(role="assistant", content="Finding SEC-001 is a critical SQL injection at line 18.", timestamp=None),
    ]

    response = assistant.ask("Show me the fix for that one", history=history)

    assert response.intent == "fix_request"
    assert "SEC-001" in response.related_finding_ids
    assert "diff" in response.answer
    assert "parameterized" in response.answer.lower() or "?" in response.answer


# =============================================================================
# 5. Robustness & Edge Cases Tests
# =============================================================================

def test_edge_case_empty_question():
    """Verifies graceful handling of empty or whitespace question without errors."""
    res = _build_test_analysis_result()
    assistant = ChatAssistant(analysis_result=res, code="", language="python", retriever=MockRetriever())

    response = assistant.ask("   ")
    assert response is not None
    assert len(response.answer) > 0
    assert response.grounded is False


def test_edge_case_no_findings():
    """Verifies assistant handles an analysis result containing zero findings gracefully."""
    empty_res = AnalysisResult(
        findings=[],
        counts_by_severity={},
        counts_by_agent={},
        language="python",
        filename="clean.py",
    )
    assistant = ChatAssistant(analysis_result=empty_res, code="x = 1", language="python", retriever=MockRetriever())

    response = assistant.ask("What should I fix first?")
    assert response.intent == "summary_request"
    assert "no security vulnerabilities" in response.answer.lower() or "0" in response.answer


def test_edge_case_bad_finding_number():
    """Verifies that an out-of-bounds finding number returns a helpful message without crashing."""
    res = _build_test_analysis_result()
    assistant = ChatAssistant(analysis_result=res, code="", language="python", retriever=MockRetriever())

    response = assistant.ask("Explain finding 99")
    assert "does not exist" in response.answer or "out of range" in response.answer or "not found" in response.answer
    assert response.grounded is False


def test_edge_case_very_long_input():
    """Verifies that excessively long input queries are handled safely without timeouts or crashes."""
    res = _build_test_analysis_result()
    assistant = ChatAssistant(analysis_result=res, code="", language="python", retriever=MockRetriever())

    long_q = "Why is line 18 flagged? " + ("explain please " * 300)
    response = assistant.ask(long_q)
    assert response is not None
    assert response.intent in ("finding_explanation", "concept_question")


# =============================================================================
# 6. End-to-End Orchestrator & Real ChromaDB KB Tests
# =============================================================================

def test_chat_assistant_e2e_python_sample():
    """Verifies end-to-end ChatAssistant on planted_security.py with real orchestrator pipeline."""
    sample_path = SAMPLE_DIR / "python" / "planted_security.py"
    assert sample_path.exists()
    code = sample_path.read_text(encoding="utf-8")

    # Run complete analysis
    result = analyze(code, language="python", filename="planted_security.py")
    assert len(result.findings) >= 4
    assert len(result.remediations) >= 4

    # Instantiate assistant via orchestrator hook
    assistant = create_chat_assistant(result=result, code=code, language="python")
    assert isinstance(assistant, ChatAssistant)

    # 1. Ask about SQL injection finding
    resp_sqli = assistant.ask("Why is the SQL injection flagged in fetch_user_data?")
    assert resp_sqli.intent in ("finding_explanation", "fix_request")
    assert len(resp_sqli.related_finding_ids) >= 1
    assert resp_sqli.grounded is True

    # 2. Ask for remediation
    resp_fix = assistant.ask("How do I fix finding 1?")
    assert resp_fix.intent == "fix_request"
    assert "```diff" in resp_fix.answer

    # 3. Ask for code summary
    resp_sum = assistant.ask("What should I fix first?")
    assert resp_sum.intent == "summary_request"
    assert "Score" in resp_sum.answer or "Health" in resp_sum.answer


def test_chat_assistant_e2e_java_sample():
    """Verifies end-to-end ChatAssistant on PlantedSecurity.java with real orchestrator pipeline."""
    sample_path = SAMPLE_DIR / "java" / "PlantedSecurity.java"
    assert sample_path.exists()
    code = sample_path.read_text(encoding="utf-8")

    # Run complete analysis
    result = analyze(code, language="java", filename="PlantedSecurity.java")
    assert len(result.findings) >= 4
    assert len(result.remediations) >= 4

    # Instantiate assistant via orchestrator hook
    assistant = create_chat_assistant(result=result, code=code, language="java")
    assert isinstance(assistant, ChatAssistant)

    # 1. Ask about secret in Java code
    resp_sec = assistant.ask("Tell me about the hardcoded secret password")
    assert len(resp_sec.related_finding_ids) >= 1
    assert resp_sec.grounded is True

    # 2. Ask general concept question
    resp_concept = assistant.ask("What is CWE-89 SQL injection?")
    assert resp_concept.intent == "concept_question"
    assert resp_concept.grounded is True
    assert len(resp_concept.citations) >= 1

