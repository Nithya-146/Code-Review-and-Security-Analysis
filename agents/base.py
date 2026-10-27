"""
Base Agent Interface for Code Review & Security Analysis.

Defines the abstract BaseAgent class that all specialized agents
(Code Analysis Agent, Security Agent) must implement. Reuses the existing
Milestone 1 parsers for syntax validation and metadata extraction.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import logging

from app.schemas import Finding
from app.python_parser import validate_python
from app.java_parser import validate_java

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """
    Abstract base class for all analysis agents in the system.
    Enforces a uniform interface for running analysis on Python or Java source code.
    """

    def __init__(self, agent_name: Optional[str] = None) -> None:
        """Initializes the base agent with a descriptive identifier."""
        self.agent_name = agent_name or self.__class__.__name__

    def parse_code(self, code: str, language: str) -> Dict[str, Any]:
        """
        Parses and pre-validates source code using the existing Milestone 1 parsers.

        Args:
            code: Source code text to parse.
            language: Programming language ('python' or 'java').

        Returns:
            Dictionary containing 'is_valid', 'error', and 'metadata'.
        """
        lang = language.strip().lower()
        if lang in ("python", "py"):
            return validate_python(code)
        elif lang in ("java",):
            return validate_java(code)
        else:
            logger.warning("Unsupported language requested: %s", language)
            return {
                "is_valid": False,
                "error": f"Unsupported language: {language}. Supported: python, java.",
                "metadata": {}
            }

    @abstractmethod
    def run(self, code: str, language: str, filename: str = "unknown") -> List[Finding]:
        """
        Executes code review analysis on the provided source code.

        Args:
            code: Source code string to inspect.
            language: Programming language ('python' or 'java').
            filename: Target filename for location reporting.

        Returns:
            List of Finding objects identified by this agent.
        """
        pass
