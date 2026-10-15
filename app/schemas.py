from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

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

# 3. Model for Individual Security Findings
class SecurityFinding(BaseModel):
    id: str = Field(description="Unique finding identifier, e.g., SEC-001")
    cwe_id: str = Field(description="Common Weakness Enumeration ID, e.g., CWE-89")
    owasp_category: OWASPCategory
    severity: SeverityLevel
    line_start: int
    line_end: int
    title: str
    description: str

# 4. Model for Individual Code Quality Smells
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

# 6. Top-Level State & Final Review Report Schema
class ReviewReport(BaseModel):
    submission_id: str
    language: str  # "python" or "java"
    is_valid_syntax: bool
    ast_metadata: Dict[str, Any] = Field(default_factory=dict)
    security_findings: List[SecurityFinding] = Field(default_factory=list)
    quality_findings: List[QualityFinding] = Field(default_factory=list)
    remediations: List[RemediationItem] = Field(default_factory=list)
    pr_summary_markdown: Optional[str] = None