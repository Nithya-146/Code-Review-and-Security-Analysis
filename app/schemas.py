from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator

# 1. Standard Severity Levels
class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

# 2. OWASP Top 10:2025 Taxonomy Enum
class OWASPCategory(str, Enum):
    A01 = "A01:2025-Broken Access Control"
    A02 = "A02:2025-Security Misconfiguration"
    A03 = "A03:2025-Software Supply Chain Failures"
    A04 = "A04:2025-Cryptographic Failures"
    A05 = "A05:2025-Injection"
    A06 = "A06:2025-Insecure Design"
    A07 = "A07:2025-Authentication Failures"
    A08 = "A08:2025-Software or Data Integrity Failures"
    A09 = "A09:2025-Security Logging and Alerting Failures"
    A10 = "A10:2025-Mishandling of Exceptional Conditions"

# 3. Model for Individual Security Findings (Milestone 1 backward compatibility)
class SecurityFinding(BaseModel):
    id: str = Field(description="Unique finding identifier, e.g., SEC-001")
    cwe_id: str = Field(description="Common Weakness Enumeration ID, e.g., CWE-89")
    owasp_category: OWASPCategory
    severity: SeverityLevel
    line_start: int
    line_end: int
    title: str
    description: str

# 4. Model for Individual Code Quality Smells (Milestone 1 backward compatibility)
class QualityFinding(BaseModel):
    id: str = Field(description="Unique finding identifier, e.g., QLT-001")
    smell_type: str = Field(description="e.g., Magic Numbers, Deep Nesting, Long Method")
    line_start: int
    line_end: int
    message: str

# 5. Model for Remediation Fixes (Milestone 1 backward compatibility)
class RemediationItem(BaseModel):
    finding_id: str
    explanation: str
    original_code: str
    replacement_code: str

# 6. Unified Model for Individual Analysis & Security Findings (Milestone 2)
class Finding(BaseModel):
    id: str = Field(description="Unique finding identifier, e.g., CODE-001 or SEC-001")
    title: str = Field(description="Short descriptive title of the finding")
    category: str = Field(description="Category of finding, e.g., Code Smell, Complexity, Maintainability")
    agent: str = Field(description="Agent identifier, e.g., 'code_analysis' or 'security_analysis'")
    severity: SeverityLevel = Field(description="Finding severity: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    severity_score: float = Field(ge=0.0, le=10.0, description="Severity score from 0.0 to 10.0")

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: Any) -> Any:
        """Converts case-insensitive strings (e.g. 'High', 'critical') to SeverityLevel enum."""
        if isinstance(v, str):
            v_upper = v.strip().upper()
            if v_upper in SeverityLevel.__members__:
                return SeverityLevel[v_upper]
        return v
    file: str = Field(default="", description="Source filename or relative path")
    line_start: int = Field(ge=1, description="Starting line number (1-indexed)")
    line_end: int = Field(ge=1, description="Ending line number (1-indexed)")
    code_snippet: Optional[str] = Field(default="", description="Relevant code snippet")
    explanation: str = Field(description="Explanation of the issue found")
    suggestion: Optional[str] = Field(default="", description="Actionable recommendation to resolve the issue")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    source: str = Field(default="rule", description="Finding origin: 'rule' or 'llm'")
    # Optional fields reserved for Step 2 (Security Agent)
    owasp_category: Optional[OWASPCategory] = Field(default=None, description="Associated OWASP category")
    cwe_id: Optional[str] = Field(default=None, description="Common Weakness Enumeration ID, e.g., CWE-89")
    evidence: Optional[str] = Field(default=None, description="Detailed evidence, AST trace, or RAG reference")

# 7. Top-Level State & Final Review Report Schema
class ReviewReport(BaseModel):
    submission_id: str
    language: str  # "python" or "java"
    is_valid_syntax: bool
    ast_metadata: Dict[str, Any] = Field(default_factory=dict)
    security_findings: List[SecurityFinding] = Field(default_factory=list)
    quality_findings: List[QualityFinding] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    remediations: List[Any] = Field(default_factory=list)
    pr_summary_markdown: Optional[str] = None


# 8. Milestone 3 Step 1 Schemas

class RemediationResult(BaseModel):
    finding_id: str = Field(description="Unique identifier of the finding being remediated")
    explanation: str = Field(description="Explanation of why this pattern is problematic")
    fix_summary: str = Field(description="Concise summary of the remediation applied")
    original_code: str = Field(description="Original vulnerable or smell-inducing code snippet")
    corrected_code: str = Field(description="Remediated, safe replacement code snippet")
    best_practice: str = Field(description="Best practice guidance for future implementation")
    references: List[str] = Field(default_factory=list, description="Knowledge base sources and chunk references")
    verified: bool = Field(default=False, description="True if fix passes syntax and verification scans")
    verification_note: str = Field(default="", description="Detailed note explaining verification result")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Remediation confidence score")


class CodeHealthScore(BaseModel):
    score: int = Field(ge=0, le=100, description="Deterministic health score (0-100)")
    grade: str = Field(description="Letter grade: A, B, C, D, or F")
    breakdown_by_severity: Dict[str, int] = Field(default_factory=dict, description="Finding counts categorized by severity")
    penalty_details: Dict[str, int] = Field(default_factory=dict, description="Deducted penalty points categorized by severity")


class PrioritizedFix(BaseModel):
    finding_id: str = Field(description="Finding identifier")
    title: str = Field(description="Finding title")
    severity: SeverityLevel = Field(description="Severity tier")
    effort: str = Field(description="Estimated remediation effort: Low, Medium, or High")
    reason: str = Field(description="Short rationale for why this fix should be prioritized")


class PRSummary(BaseModel):
    executive_overview: str = Field(description="2-4 sentence executive overview")
    severity_breakdown: Dict[str, int] = Field(default_factory=dict, description="Counts by severity")
    top_risks: List[str] = Field(default_factory=list, description="Top security risks and quality concerns")
    prioritized_fixes: List[PrioritizedFix] = Field(default_factory=list, description="Ordered prioritized fix list")
    health_score: CodeHealthScore = Field(description="Calculated code health score")
    markdown: str = Field(description="Full pull-request-style markdown report")


# 9. Unified Multi-Agent Analysis Result (Milestone 2 & 3)
class AnalysisResult(BaseModel):
    findings: List[Finding] = Field(default_factory=list, description="Unified, deduplicated findings sorted by severity descending and line start")
    counts_by_severity: Dict[str, int] = Field(default_factory=dict, description="Counts of findings by severity level")
    counts_by_agent: Dict[str, int] = Field(default_factory=dict, description="Counts of findings by analyzing agent")
    per_agent_runtime: Dict[str, float] = Field(default_factory=dict, description="Execution runtimes in seconds per agent")
    agent_runtimes: Dict[str, float] = Field(default_factory=dict, description="Runtimes dictionary alias")
    language: str = Field(default="python", description="Target programming language")
    filename: str = Field(default="unknown", description="Analyzed file name")
    run_status: Dict[str, str] = Field(default_factory=dict, description="Execution status per agent, e.g. SUCCESS or ERROR")
    remediations: List[RemediationResult] = Field(default_factory=list, description="Remediation fix results for findings")
    pr_summary: Optional[PRSummary] = Field(default=None, description="Generated pull request summary report")
    health_score: Optional[CodeHealthScore] = Field(default=None, description="Calculated code health score")


# 10. Milestone 3 Step 2 Schemas (Conversational Assistant)

class ChatMessage(BaseModel):
    role: str = Field(description="Message role: 'user' or 'assistant'")
    content: str = Field(description="Message text content")
    timestamp: Optional[str] = Field(default=None, description="ISO timestamp or formatted time string")


class Citation(BaseModel):
    source: str = Field(description="Source document name, e.g. A05_injection.md")
    section: str = Field(default="", description="Section header or chunk identifier")
    chunk_id: Optional[str] = Field(default=None, description="Identifier of the knowledge base chunk")
    snippet: str = Field(description="Short relevant snippet excerpt from the source")
    relevance_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Similarity or relevance score")


class ChatResponse(BaseModel):
    answer: str = Field(description="Assistant response text")
    citations: List[Citation] = Field(default_factory=list, description="Citations to knowledge base sources")
    related_finding_ids: List[str] = Field(default_factory=list, description="IDs of findings referenced in answer")
    grounded: bool = Field(default=False, description="True if answer is grounded in retrieved knowledge base facts")
    follow_up_suggestions: List[str] = Field(default_factory=list, description="2-3 relevant follow-up questions")
    intent: str = Field(description="Detected user intent, e.g. finding_explanation, fix_request, concept_question, best_practice, summary_request, or out_of_scope")
