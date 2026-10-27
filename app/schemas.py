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

# 5. Model for Remediation Fixes
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
    remediations: List[RemediationItem] = Field(default_factory=list)
    pr_summary_markdown: Optional[str] = None