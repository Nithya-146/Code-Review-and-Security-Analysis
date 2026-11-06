"""
app.agents package - compatibility aliases for agents module.
"""

from agents.base import BaseAgent
from agents.code_analysis import CodeAnalysisAgent
from agents.security import SecurityAgent
from agents.remediation_agent import RemediationAgent
from agents.pr_summary_agent import PRSummaryAgent
from agents.chat_assistant import ChatAssistant

__all__ = [
    "BaseAgent",
    "CodeAnalysisAgent",
    "SecurityAgent",
    "RemediationAgent",
    "PRSummaryAgent",
    "ChatAssistant",
]
