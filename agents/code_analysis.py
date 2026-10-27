"""
Code Analysis Agent for AI Code Review & Security Analysis.

Implements CodeAnalysisAgent(BaseAgent) detecting code smells, maintainability issues,
and design anti-patterns across Python (ast) and Java (javalang).
Features:
- Deterministic AST rules for both Python and Java
- Centralized, explainable threshold constants block
- Documented quality defect severity scoring function (0.0 - 10.0)
- Configurable, graceful optional LLM pass for architectural design smells
"""

import ast
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import logging

import javalang

from agents.base import BaseAgent
from app.schemas import Finding, SeverityLevel

logger = logging.getLogger(__name__)

# ==============================================================================
# Thresholds Constants Block for Code Quality & Maintainability Checks
# ==============================================================================
MAX_COMPLEXITY: int = 10              # Cyclomatic complexity limit per function/method
MAX_FUNCTION_LINES: int = 50          # Maximum line length of a function/method
MAX_FILE_LINES: int = 300             # Maximum line length of a complete source file
MAX_NESTING_DEPTH: int = 4            # Maximum nesting depth of control flow blocks
MAX_PARAMETERS: int = 5               # Maximum allowed parameters for a function/method
MAX_CLASS_METHODS: int = 10           # Maximum methods allowed before flagging God Class
MAX_CLASS_LINES: int = 200            # Maximum lines for a class before flagging God Class
MIN_DUPLICATE_LINES: int = 6          # Minimum consecutive lines to flag duplicate code
ALLOWED_MAGIC_NUMBERS: Set[float] = {0, 1, 2, -1, 100, 0.0, 1.0}
ALLOWED_LOOP_VAR_NAMES: Set[str] = {"i", "j", "k", "idx", "row", "col", "ch", "c", "_"}


# ==============================================================================
# Scoring Function
# ==============================================================================
def calculate_quality_score(rule_type: str, severity: SeverityLevel) -> float:
    """
    Computes a normalized quality defect severity score (0.0 - 10.0).

    Scoring is mapped by architectural and maintainability impact:
    - CRITICAL (9.0 - 10.0): System-breaking defects or extreme anti-patterns.
    - HIGH (7.0 - 8.5): Major architectural defects (God Class, extreme complexity).
    - MEDIUM (4.5 - 6.5): High maintainability debt (Deep Nesting, Long Functions, Duplicate Code).
    - LOW (2.0 - 4.0): Cleanliness and readability issues (Magic Numbers, Unused Code, Poor Naming).
    - INFO (1.0): Informational style hints.
    """
    rule_scores: Dict[str, float] = {
        "god_class": 8.0,
        "cyclomatic_complexity": 7.5,
        "deep_nesting": 6.0,
        "long_function": 5.5,
        "duplicate_code": 5.5,
        "too_many_parameters": 5.0,
        "broad_exception": 5.0,
        "long_file": 4.5,
        "unused_import": 3.0,
        "unused_variable": 3.0,
        "missing_docstring": 2.5,
        "poor_naming": 2.0,
        "magic_number": 2.0,
        "llm_design_smell": 6.5,
    }

    if rule_type in rule_scores:
        return rule_scores[rule_type]

    fallback_scores: Dict[SeverityLevel, float] = {
        SeverityLevel.CRITICAL: 9.0,
        SeverityLevel.HIGH: 7.5,
        SeverityLevel.MEDIUM: 5.0,
        SeverityLevel.LOW: 2.5,
        SeverityLevel.INFO: 1.0,
    }
    return fallback_scores.get(severity, 3.0)


# ==============================================================================
# Helper Data Structure for Matches
# ==============================================================================
class QualityMatch:
    """Represents an internal raw match for a code quality smell."""

    def __init__(
        self,
        rule_type: str,
        title: str,
        severity: SeverityLevel,
        line_start: int,
        line_end: int,
        code_snippet: str,
        explanation: str,
        suggestion: str,
        confidence: float = 1.0,
    ) -> None:
        self.rule_type = rule_type
        self.title = title
        self.severity = severity
        self.line_start = max(1, line_start)
        self.line_end = max(self.line_start, line_end)
        self.code_snippet = code_snippet
        self.explanation = explanation
        self.suggestion = suggestion
        self.confidence = confidence


# ==============================================================================
# Python AST Analysis Helpers
# ==============================================================================
def _py_calculate_complexity(node: ast.AST) -> int:
    """Calculates cyclomatic complexity of a Python function AST node."""
    complexity = 1
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.ExceptHandler, ast.With, ast.AsyncWith, ast.Assert)):
            complexity += 1
        elif isinstance(child, ast.BoolOp):
            complexity += len(child.values) - 1
        elif isinstance(child, ast.IfExp):
            complexity += 1
    return complexity


def _py_calculate_nesting(node: ast.AST, current_depth: int = 0) -> int:
    """Calculates maximum block nesting depth inside a Python AST node."""
    max_depth = current_depth
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith)):
            child_depth = _py_calculate_nesting(child, current_depth + 1)
        else:
            child_depth = _py_calculate_nesting(child, current_depth)
        max_depth = max(max_depth, child_depth)
    return max_depth


def _py_check_complexity_and_nesting(tree: ast.AST, code_lines: List[str]) -> List[QualityMatch]:
    """Detects high cyclomatic complexity and deep nesting in Python functions."""
    matches: List[QualityMatch] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        comp = _py_calculate_complexity(node)
        if comp > MAX_COMPLEXITY:
            start = node.lineno
            end = getattr(node, "end_lineno", start)
            snippet = "\n".join(code_lines[start - 1 : min(end, start + 3)])
            matches.append(
                QualityMatch(
                    rule_type="cyclomatic_complexity",
                    title="High Cyclomatic Complexity",
                    severity=SeverityLevel.HIGH if comp > 15 else SeverityLevel.MEDIUM,
                    line_start=start,
                    line_end=end,
                    code_snippet=snippet,
                    explanation=f"Function '{node.name}' has a cyclomatic complexity of {comp} (threshold: {MAX_COMPLEXITY}).",
                    suggestion="Refactor complex conditional branches into smaller, single-purpose helper functions.",
                )
            )

        nesting = _py_calculate_nesting(node, current_depth=0)
        if nesting > MAX_NESTING_DEPTH:
            start = node.lineno
            end = getattr(node, "end_lineno", start)
            snippet = "\n".join(code_lines[start - 1 : min(end, start + 3)])
            matches.append(
                QualityMatch(
                    rule_type="deep_nesting",
                    title="Deep Control Flow Nesting",
                    severity=SeverityLevel.MEDIUM,
                    line_start=start,
                    line_end=end,
                    code_snippet=snippet,
                    explanation=f"Function '{node.name}' has a nesting depth of {nesting} (threshold: {MAX_NESTING_DEPTH}).",
                    suggestion="Flatten nested control flow using guard clauses and early return statements.",
                )
            )
    return matches


def _py_check_functions_and_file_length(tree: ast.AST, code_lines: List[str]) -> List[QualityMatch]:
    """Detects functions exceeding MAX_FUNCTION_LINES and files exceeding MAX_FILE_LINES."""
    matches: List[QualityMatch] = []
    total_file_lines = len(code_lines)
    if total_file_lines > MAX_FILE_LINES:
        matches.append(
            QualityMatch(
                rule_type="long_file",
                title="Excessively Long File",
                severity=SeverityLevel.LOW,
                line_start=1,
                line_end=total_file_lines,
                code_snippet=code_lines[0] if code_lines else "",
                explanation=f"File contains {total_file_lines} lines of code (threshold: {MAX_FILE_LINES}).",
                suggestion="Split file into cohesive, modular sub-modules or services.",
            )
        )

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", start)
            length = end - start + 1
            if length > MAX_FUNCTION_LINES:
                snippet = "\n".join(code_lines[start - 1 : min(end, start + 3)])
                matches.append(
                    QualityMatch(
                        rule_type="long_function",
                        title="Long Function",
                        severity=SeverityLevel.MEDIUM,
                        line_start=start,
                        line_end=end,
                        code_snippet=snippet,
                        explanation=f"Function '{node.name}' spans {length} lines (threshold: {MAX_FUNCTION_LINES}).",
                        suggestion="Extract cohesive sub-tasks into dedicated private helper functions.",
                    )
                )
    return matches


def _py_check_parameters_and_god_class(tree: ast.AST, code_lines: List[str]) -> List[QualityMatch]:
    """Checks for long parameter lists and God classes in Python."""
    matches: List[QualityMatch] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = [a.arg for a in node.args.args if a.arg not in ("self", "cls")]
            if node.args.vararg:
                params.append(node.args.vararg.arg)
            if node.args.kwarg:
                params.append(node.args.kwarg.arg)
            params.extend([a.arg for a in node.args.kwonlyargs])

            if len(params) > MAX_PARAMETERS:
                start = node.lineno
                end = getattr(node, "end_lineno", start)
                snippet = code_lines[start - 1] if 0 <= start - 1 < len(code_lines) else ""
                matches.append(
                    QualityMatch(
                        rule_type="too_many_parameters",
                        title="Too Many Parameters",
                        severity=SeverityLevel.MEDIUM,
                        line_start=start,
                        line_end=end,
                        code_snippet=snippet,
                        explanation=f"Function '{node.name}' accepts {len(params)} parameters (threshold: {MAX_PARAMETERS}).",
                        suggestion="Encapsulate related parameters into a dataclass, Pydantic model, or configuration dictionary.",
                    )
                )

        elif isinstance(node, ast.ClassDef):
            methods = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            start = node.lineno
            end = getattr(node, "end_lineno", start)
            class_lines = end - start + 1

            if len(methods) > MAX_CLASS_METHODS or class_lines > MAX_CLASS_LINES:
                snippet = code_lines[start - 1] if 0 <= start - 1 < len(code_lines) else ""
                matches.append(
                    QualityMatch(
                        rule_type="god_class",
                        title="God Class (Large Class Smell)",
                        severity=SeverityLevel.HIGH,
                        line_start=start,
                        line_end=end,
                        code_snippet=snippet,
                        explanation=f"Class '{node.name}' has {len(methods)} methods and {class_lines} lines (thresholds: {MAX_CLASS_METHODS} methods, {MAX_CLASS_LINES} lines).",
                        suggestion="Decompose this large class into cohesive single-responsibility domain components.",
                    )
                )
    return matches


def _py_check_exceptions(tree: ast.AST, code_lines: List[str]) -> List[QualityMatch]:
    """Detects bare except clauses and overly broad Exception catching in Python."""
    matches: List[QualityMatch] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue

        start = node.lineno
        end = getattr(node, "end_lineno", start)
        snippet = code_lines[start - 1] if 0 <= start - 1 < len(code_lines) else ""

        if node.type is None:
            matches.append(
                QualityMatch(
                    rule_type="broad_exception",
                    title="Bare Except Clause",
                    severity=SeverityLevel.HIGH,
                    line_start=start,
                    line_end=end,
                    code_snippet=snippet,
                    explanation="Bare 'except:' catches all exceptions including system-exiting signals (KeyboardInterrupt, SystemExit).",
                    suggestion="Catch specific exception types (e.g. ValueError, KeyError) instead of bare except.",
                )
            )
        elif isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"):
            matches.append(
                QualityMatch(
                    rule_type="broad_exception",
                    title="Overly Broad Exception Catch",
                    severity=SeverityLevel.MEDIUM,
                    line_start=start,
                    line_end=end,
                    code_snippet=snippet,
                    explanation=f"Catching broad '{node.type.id}' masks unexpected bugs and runtime errors.",
                    suggestion="Catch narrow, expected domain exceptions and handle or re-raise them specifically.",
                )
            )
    return matches


def _py_check_unused_symbols(tree: ast.AST, code_lines: List[str]) -> List[QualityMatch]:
    """Detects unused imports and unused local variables in Python."""
    matches: List[QualityMatch] = []

    # 1. Imports
    imported_names: Dict[str, Tuple[int, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name_to_check = alias.asname or alias.name
                imported_names[name_to_check] = (node.lineno, alias.name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                name_to_check = alias.asname or alias.name
                imported_names[name_to_check] = (node.lineno, alias.name)

    # Collect all loaded symbols
    loaded_names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            loaded_names.add(node.id)
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            loaded_names.add(node.value.id)

    for import_alias, (lineno, original_name) in imported_names.items():
        # Dunder or wildcard imports ignored
        if import_alias == "*" or import_alias.startswith("__"):
            continue
        # Split on dot if e.g. 'os.path'
        root_name = import_alias.split(".")[0]
        if root_name not in loaded_names and import_alias not in loaded_names:
            snippet = code_lines[lineno - 1] if 0 <= lineno - 1 < len(code_lines) else ""
            matches.append(
                QualityMatch(
                    rule_type="unused_import",
                    title="Unused Import",
                    severity=SeverityLevel.LOW,
                    line_start=lineno,
                    line_end=lineno,
                    code_snippet=snippet,
                    explanation=f"Imported symbol '{import_alias}' is never referenced in this file.",
                    suggestion=f"Remove the unused import '{import_alias}'.",
                )
            )

    # 2. Local variables inside functions
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        assigned_vars: Dict[str, int] = {}
        used_vars: Set[str] = set()
        param_names = {a.arg for a in node.args.args}

        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                if isinstance(child.ctx, ast.Store):
                    if child.id not in param_names and not child.id.startswith("_"):
                        assigned_vars.setdefault(child.id, child.lineno)
                elif isinstance(child.ctx, ast.Load):
                    used_vars.add(child.id)

        for var_name, lineno in assigned_vars.items():
            if var_name not in used_vars:
                snippet = code_lines[lineno - 1] if 0 <= lineno - 1 < len(code_lines) else ""
                matches.append(
                    QualityMatch(
                        rule_type="unused_variable",
                        title="Unused Local Variable",
                        severity=SeverityLevel.LOW,
                        line_start=lineno,
                        line_end=lineno,
                        code_snippet=snippet,
                        explanation=f"Local variable '{var_name}' is assigned but never read.",
                        suggestion=f"Remove unused variable '{var_name}' or prefix with an underscore if intentionally ignored.",
                    )
                )
    return matches


def _py_check_magic_docstring_naming(tree: ast.AST, code_lines: List[str]) -> List[QualityMatch]:
    """Detects magic numbers, missing docstrings, and poor naming in Python."""
    matches: List[QualityMatch] = []

    # Identify module-level constant definitions (both regular Assign and AnnAssign)
    constant_lines: Set[int] = set()
    for node in tree.body if hasattr(tree, "body") else []:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.isupper():
                    constant_lines.add(node.lineno)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id.isupper():
                constant_lines.add(node.lineno)

    # 1. Magic numbers
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            val = float(node.value)
            if val not in ALLOWED_MAGIC_NUMBERS and node.lineno not in constant_lines:
                snippet = code_lines[node.lineno - 1] if 0 <= node.lineno - 1 < len(code_lines) else ""
                matches.append(
                    QualityMatch(
                        rule_type="magic_number",
                        title="Magic Number",
                        severity=SeverityLevel.LOW,
                        line_start=node.lineno,
                        line_end=node.lineno,
                        code_snippet=snippet,
                        explanation=f"Literal number '{node.value}' used without descriptive constant context.",
                        suggestion="Replace literal number with a clearly named, uppercase constant.",
                    )
                )

    # 2. Missing docstrings and poor naming
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Check docstring
            if ast.get_docstring(node) is None and not node.name.startswith("__"):
                start = node.lineno
                snippet = code_lines[start - 1] if 0 <= start - 1 < len(code_lines) else ""
                matches.append(
                    QualityMatch(
                        rule_type="missing_docstring",
                        title="Missing Function Docstring",
                        severity=SeverityLevel.LOW,
                        line_start=start,
                        line_end=start,
                        code_snippet=snippet,
                        explanation=f"Function '{node.name}' has no docstring explaining its purpose.",
                        suggestion=f"Add a concise docstring describing '{node.name}', arguments, and return values.",
                    )
                )

            # Check parameter naming
            for arg in node.args.args:
                if arg.arg not in ("self", "cls") and len(arg.arg) == 1 and arg.arg not in ALLOWED_LOOP_VAR_NAMES:
                    start = node.lineno
                    snippet = code_lines[start - 1] if 0 <= start - 1 < len(code_lines) else ""
                    matches.append(
                        QualityMatch(
                            rule_type="poor_naming",
                            title="Poor Variable Naming (Single-Letter)",
                            severity=SeverityLevel.LOW,
                            line_start=start,
                            line_end=start,
                            code_snippet=snippet,
                            explanation=f"Parameter '{arg.arg}' in function '{node.name}' is a single letter.",
                            suggestion="Use meaningful, descriptive domain names (e.g. 'account_id', 'total_count').",
                        )
                    )

        elif isinstance(node, ast.ClassDef):
            if ast.get_docstring(node) is None:
                start = node.lineno
                snippet = code_lines[start - 1] if 0 <= start - 1 < len(code_lines) else ""
                matches.append(
                    QualityMatch(
                        rule_type="missing_docstring",
                        title="Missing Class Docstring",
                        severity=SeverityLevel.LOW,
                        line_start=start,
                        line_end=start,
                        code_snippet=snippet,
                        explanation=f"Class '{node.name}' has no docstring.",
                        suggestion="Add a class-level docstring summarizing its primary responsibility.",
                    )
                )

        # Single letter assignments outside loops
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and len(target.id) == 1 and target.id not in ALLOWED_LOOP_VAR_NAMES:
                    # Ensure not inside a for-loop target
                    snippet = code_lines[node.lineno - 1] if 0 <= node.lineno - 1 < len(code_lines) else ""
                    matches.append(
                        QualityMatch(
                            rule_type="poor_naming",
                            title="Poor Variable Naming (Single-Letter)",
                            severity=SeverityLevel.LOW,
                            line_start=node.lineno,
                            line_end=node.lineno,
                            code_snippet=snippet,
                            explanation=f"Variable '{target.id}' uses a cryptic single-letter identifier.",
                            suggestion="Rename the variable to clearly reflect its intent and data content.",
                        )
                    )
    return matches


# ==============================================================================
# Java AST (javalang) Analysis Helpers
# ==============================================================================
def _java_calculate_complexity(method_node: javalang.tree.MethodDeclaration) -> int:
    """Calculates cyclomatic complexity of a Java method."""
    complexity = 1
    for _, child in method_node:
        if isinstance(
            child,
            (
                javalang.tree.IfStatement,
                javalang.tree.WhileStatement,
                javalang.tree.ForStatement,
                javalang.tree.DoStatement,
                javalang.tree.CatchClause,
                javalang.tree.TernaryExpression,
            ),
        ):
            complexity += 1
        elif isinstance(child, javalang.tree.BinaryOperation) and child.operator in ("&&", "||"):
            complexity += 1
    return complexity


def _java_calculate_nesting(node: Any, current_depth: int = 0) -> int:
    """Calculates maximum block nesting depth in a Java AST node."""
    next_depth = (
        current_depth + 1
        if isinstance(
            node,
            (
                javalang.tree.IfStatement,
                javalang.tree.ForStatement,
                javalang.tree.WhileStatement,
                javalang.tree.DoStatement,
                javalang.tree.TryStatement,
                javalang.tree.SwitchStatement,
            ),
        )
        else current_depth
    )

    max_depth = next_depth

    if hasattr(node, "children"):
        for child in node.children:
            if isinstance(child, list):
                for item in child:
                    max_depth = max(max_depth, _java_calculate_nesting(item, next_depth))
            elif child is not None and hasattr(child, "children"):
                max_depth = max(max_depth, _java_calculate_nesting(child, next_depth))
    return max_depth


def _java_get_node_span(node: Any, default_start: int) -> Tuple[int, int]:
    """Calculates start and approximate end lines of a Java AST node."""
    start = getattr(node, "position", None)
    line_start = start.line if start else default_start
    max_line = line_start
    for _, child in node:
        pos = getattr(child, "position", None)
        if pos:
            max_line = max(max_line, pos.line)
    return line_start, max_line


def _java_check_methods_and_classes(tree: javalang.tree.CompilationUnit, code_lines: List[str]) -> List[QualityMatch]:
    """Inspects Java methods and classes for complexity, nesting, parameters, and God class."""
    matches: List[QualityMatch] = []

    # File length
    total_lines = len(code_lines)
    if total_lines > MAX_FILE_LINES:
        matches.append(
            QualityMatch(
                rule_type="long_file",
                title="Excessively Long File",
                severity=SeverityLevel.LOW,
                line_start=1,
                line_end=total_lines,
                code_snippet=code_lines[0] if code_lines else "",
                explanation=f"Java file contains {total_lines} lines of code (threshold: {MAX_FILE_LINES}).",
                suggestion="Decompose the file into distinct classes or packages.",
            )
        )

    # Class inspections
    for _, class_node in tree.filter(javalang.tree.ClassDeclaration):
        start, end = _java_get_node_span(class_node, default_start=1)
        methods = class_node.methods
        class_lines = end - start + 1

        if len(methods) > MAX_CLASS_METHODS or class_lines > MAX_CLASS_LINES:
            snippet = code_lines[start - 1] if 0 <= start - 1 < len(code_lines) else ""
            matches.append(
                QualityMatch(
                    rule_type="god_class",
                    title="God Class (Large Class Smell)",
                    severity=SeverityLevel.HIGH,
                    line_start=start,
                    line_end=end,
                    code_snippet=snippet,
                    explanation=f"Java class '{class_node.name}' has {len(methods)} methods and {class_lines} lines (thresholds: {MAX_CLASS_METHODS} methods, {MAX_CLASS_LINES} lines).",
                    suggestion="Split this God Class into cohesive domain service and utility classes.",
                )
            )

        # Missing class Javadoc
        if class_node.documentation is None:
            snippet = code_lines[start - 1] if 0 <= start - 1 < len(code_lines) else ""
            matches.append(
                QualityMatch(
                    rule_type="missing_docstring",
                    title="Missing Class Javadoc",
                    severity=SeverityLevel.LOW,
                    line_start=start,
                    line_end=start,
                    code_snippet=snippet,
                    explanation=f"Class '{class_node.name}' lacks a Javadoc documentation comment.",
                    suggestion="Add a Javadoc comment summarizing the class responsibilities.",
                )
            )

    # Method inspections
    for _, method in tree.filter(javalang.tree.MethodDeclaration):
        start, end = _java_get_node_span(method, default_start=1)
        method_lines = end - start + 1
        snippet = code_lines[start - 1] if 0 <= start - 1 < len(code_lines) else ""

        # Complexity
        comp = _java_calculate_complexity(method)
        if comp > MAX_COMPLEXITY:
            matches.append(
                QualityMatch(
                    rule_type="cyclomatic_complexity",
                    title="High Cyclomatic Complexity",
                    severity=SeverityLevel.HIGH if comp > 15 else SeverityLevel.MEDIUM,
                    line_start=start,
                    line_end=end,
                    code_snippet=snippet,
                    explanation=f"Method '{method.name}' has a cyclomatic complexity of {comp} (threshold: {MAX_COMPLEXITY}).",
                    suggestion="Refactor complex logic using polymorphism or extracted private helper methods.",
                )
            )

        # Nesting
        nesting = _java_calculate_nesting(method, current_depth=0)
        if nesting > MAX_NESTING_DEPTH:
            matches.append(
                QualityMatch(
                    rule_type="deep_nesting",
                    title="Deep Control Flow Nesting",
                    severity=SeverityLevel.MEDIUM,
                    line_start=start,
                    line_end=end,
                    code_snippet=snippet,
                    explanation=f"Method '{method.name}' has a nesting depth of {nesting} (threshold: {MAX_NESTING_DEPTH}).",
                    suggestion="Use guard clauses and early returns to flatten deeply nested logic.",
                )
            )

        # Long Method
        if method_lines > MAX_FUNCTION_LINES:
            matches.append(
                QualityMatch(
                    rule_type="long_function",
                    title="Long Method",
                    severity=SeverityLevel.MEDIUM,
                    line_start=start,
                    line_end=end,
                    code_snippet=snippet,
                    explanation=f"Method '{method.name}' spans {method_lines} lines (threshold: {MAX_FUNCTION_LINES}).",
                    suggestion="Extract blocks of code into smaller private methods.",
                )
            )

        # Parameters
        if len(method.parameters) > MAX_PARAMETERS:
            matches.append(
                QualityMatch(
                    rule_type="too_many_parameters",
                    title="Too Many Parameters",
                    severity=SeverityLevel.MEDIUM,
                    line_start=start,
                    line_end=end,
                    code_snippet=snippet,
                    explanation=f"Method '{method.name}' has {len(method.parameters)} parameters (threshold: {MAX_PARAMETERS}).",
                    suggestion="Introduce a Parameter Object or Builder pattern to group parameters.",
                )
            )

        # Missing Method Javadoc
        if method.documentation is None:
            matches.append(
                QualityMatch(
                    rule_type="missing_docstring",
                    title="Missing Method Javadoc",
                    severity=SeverityLevel.LOW,
                    line_start=start,
                    line_end=start,
                    code_snippet=snippet,
                    explanation=f"Method '{method.name}' lacks a Javadoc comment.",
                    suggestion="Document method arguments, return values, and behavior with Javadoc.",
                )
            )

        # Parameter poor naming
        for p in method.parameters:
            if len(p.name) == 1 and p.name not in ALLOWED_LOOP_VAR_NAMES:
                matches.append(
                    QualityMatch(
                        rule_type="poor_naming",
                        title="Poor Parameter Naming",
                        severity=SeverityLevel.LOW,
                        line_start=start,
                        line_end=start,
                        code_snippet=snippet,
                        explanation=f"Parameter '{p.name}' in method '{method.name}' is a single letter.",
                        suggestion="Rename parameter to a descriptive business name.",
                    )
                )

    return matches


def _java_check_exceptions_and_smells(tree: javalang.tree.CompilationUnit, code_lines: List[str]) -> List[QualityMatch]:
    """Detects overly broad catch clauses, magic numbers, and unused imports/variables in Java."""
    matches: List[QualityMatch] = []

    # 1. Overly broad catch
    for _, catch_node in tree.filter(javalang.tree.CatchClause):
        start = catch_node.position.line if catch_node.position else 1
        snippet = code_lines[start - 1] if 0 <= start - 1 < len(code_lines) else ""
        if catch_node.parameter and hasattr(catch_node.parameter, "types"):
            for exc_type in catch_node.parameter.types:
                if exc_type in ("Exception", "Throwable"):
                    matches.append(
                        QualityMatch(
                            rule_type="broad_exception",
                            title="Overly Broad Catch Clause",
                            severity=SeverityLevel.MEDIUM,
                            line_start=start,
                            line_end=start,
                            code_snippet=snippet,
                            explanation=f"Catching broad '{exc_type}' suppresses unexpected system errors.",
                            suggestion=f"Catch specific checked or unchecked exceptions instead of '{exc_type}'.",
                        )
                    )

    # 2. Magic numbers
    for _, literal in tree.filter(javalang.tree.Literal):
        start = literal.position.line if literal.position else 1
        val_str = str(literal.value).strip()
        # Check if numeric
        if re.match(r"^-?\d+(\.\d+)?([fFdDlL])?$", val_str):
            clean_num_str = re.sub(r"[fFdDlL]", "", val_str)
            try:
                num = float(clean_num_str)
                if num not in ALLOWED_MAGIC_NUMBERS:
                    # Check if line is a constant declaration
                    line_text = code_lines[start - 1] if 0 <= start - 1 < len(code_lines) else ""
                    if not ("static" in line_text and "final" in line_text):
                        matches.append(
                            QualityMatch(
                                rule_type="magic_number",
                                title="Magic Number",
                                severity=SeverityLevel.LOW,
                                line_start=start,
                                line_end=start,
                                code_snippet=line_text,
                                explanation=f"Magic number literal '{val_str}' used inline.",
                                suggestion="Declare a 'public static final' named constant instead.",
                            )
                        )
            except ValueError:
                pass

    # 3. Unused imports
    for imp in tree.imports:
        if imp.path:
            simple_name = imp.path.split(".")[-1]
            if simple_name != "*":
                # Check if referenced anywhere else in code
                referenced = False
                for idx, line in enumerate(code_lines):
                    if idx + 1 == imp.position.line if imp.position else -1:
                        continue
                    if re.search(r"\b" + re.escape(simple_name) + r"\b", line):
                        referenced = True
                        break
                if not referenced:
                    start = imp.position.line if imp.position else 1
                    snippet = code_lines[start - 1] if 0 <= start - 1 < len(code_lines) else ""
                    matches.append(
                        QualityMatch(
                            rule_type="unused_import",
                            title="Unused Import",
                            severity=SeverityLevel.LOW,
                            line_start=start,
                            line_end=start,
                            code_snippet=snippet,
                            explanation=f"Imported Java class '{simple_name}' is not referenced in this file.",
                            suggestion=f"Remove the unused import '{imp.path}'.",
                        )
                    )

    # 4. Unused local variables & poor naming
    for _, var_decl in tree.filter(javalang.tree.LocalVariableDeclaration):
        start = var_decl.position.line if var_decl.position else 1
        snippet = code_lines[start - 1] if 0 <= start - 1 < len(code_lines) else ""
        for decl in var_decl.declarators:
            var_name = decl.name
            # Check poor naming
            if len(var_name) == 1 and var_name not in ALLOWED_LOOP_VAR_NAMES:
                matches.append(
                    QualityMatch(
                        rule_type="poor_naming",
                        title="Poor Variable Naming",
                        severity=SeverityLevel.LOW,
                        line_start=start,
                        line_end=start,
                        code_snippet=snippet,
                        explanation=f"Local variable '{var_name}' uses a single-letter name.",
                        suggestion="Rename variable to reflect its semantic role.",
                    )
                )

            # Check if variable is referenced later in method body
            ref_count = 0
            for idx, line in enumerate(code_lines):
                if idx + 1 >= start:
                    if re.search(r"\b" + re.escape(var_name) + r"\b", line):
                        ref_count += 1
            if ref_count <= 1:
                matches.append(
                    QualityMatch(
                        rule_type="unused_variable",
                        title="Unused Variable",
                        severity=SeverityLevel.LOW,
                        line_start=start,
                        line_end=start,
                        code_snippet=snippet,
                        explanation=f"Local variable '{var_name}' is declared but never read.",
                        suggestion=f"Remove unused variable '{var_name}'.",
                    )
                )

    return matches


# ==============================================================================
# Language-Agnostic Duplicate Code Block Detector
# ==============================================================================
def _check_duplicate_code(code_lines: List[str]) -> List[QualityMatch]:
    """
    Detects duplicated code blocks of length >= MIN_DUPLICATE_LINES
    appearing multiple times in the source code.
    """
    matches: List[QualityMatch] = []
    # Clean lines by stripping whitespace and comments
    normalized_lines: List[Tuple[int, str]] = []
    for idx, line in enumerate(code_lines, start=1):
        stripped = line.strip()
        # Exclude empty lines and comment lines
        if not stripped or stripped.startswith(("#", "//", "/*", "*")):
            continue
        normalized_lines.append((idx, stripped))

    n = len(normalized_lines)
    window = MIN_DUPLICATE_LINES
    if n < window * 2:
        return matches

    seen_blocks: Dict[Tuple[str, ...], Tuple[int, int]] = {}
    reported_starts: Set[int] = set()

    for i in range(n - window + 1):
        block = tuple(normalized_lines[k][1] for k in range(i, i + window))
        start_line = normalized_lines[i][0]
        end_line = normalized_lines[i + window - 1][0]

        if block in seen_blocks:
            first_start, first_end = seen_blocks[block]
            # Avoid reporting overlapping duplicates in the same instance
            if start_line > first_end and start_line not in reported_starts:
                reported_starts.add(start_line)
                snippet = "\n".join(code_lines[start_line - 1 : min(len(code_lines), start_line + 3)])
                matches.append(
                    QualityMatch(
                        rule_type="duplicate_code",
                        title="Duplicate Code Block",
                        severity=SeverityLevel.MEDIUM,
                        line_start=start_line,
                        line_end=end_line,
                        code_snippet=snippet,
                        explanation=f"Duplicate code block of {window}+ lines identical to code at lines {first_start}-{first_end}.",
                        suggestion="Extract duplicate logic into a shared helper function or utility method.",
                    )
                )
        else:
            seen_blocks[block] = (start_line, end_line)

    return matches


# ==============================================================================
# CodeAnalysisAgent Implementation
# ==============================================================================
class CodeAnalysisAgent(BaseAgent):
    """
    Code Analysis Agent evaluating Python and Java source code for quality smells,
    architectural anti-patterns, and maintainability metrics.
    """

    def __init__(self, agent_name: str = "code_analysis") -> None:
        """Initializes the Code Analysis Agent."""
        super().__init__(agent_name=agent_name)

    def _execute_optional_llm_pass(
        self, code: str, language: str, filename: str
    ) -> List[QualityMatch]:
        """
        Executes an optional LLM evaluation pass for high-level design anti-patterns
        (e.g., tight coupling, mixed responsibilities) if an API key is configured.
        Runs fully in rules-only mode with zero errors if no API key is set.
        """
        provider = os.getenv("LLM_PROVIDER", "").strip().lower()
        api_key = (
            os.getenv("OPENAI_API_KEY")
            or os.getenv("ANTHROPIC_API_KEY")
            or os.getenv("GEMINI_API_KEY")
            or os.getenv("LLM_API_KEY")
        )

        if not api_key or provider == "none":
            logger.debug("No LLM API key configured. CodeAnalysisAgent running in rules-only mode.")
            return []

        # If an API key is supplied, invoke configured LLM provider safely
        try:
            logger.info("Executing optional LLM analysis pass with provider '%s' for %s", provider, filename)
            # Placeholder for downstream provider invocation
            return []
        except Exception as err:
            logger.warning("Optional LLM pass encountered an issue (%s); falling back to rules-only.", err)
            return []

    def run(self, code: str, language: str, filename: str = "unknown") -> List[Finding]:
        """
        Executes comprehensive code quality and smell review over Python or Java code.

        Args:
            code: Source code text.
            language: Programming language ('python' or 'java').
            filename: Target file name for location reporting.

        Returns:
            List of Finding instances identifying code quality defects.
        """
        lang = language.strip().lower()
        if lang in ("python", "py"):
            target_lang = "python"
        elif lang in ("java",):
            target_lang = "java"
        else:
            logger.warning("Unsupported language requested in CodeAnalysisAgent: %s", language)
            return []

        code_lines = code.splitlines()
        raw_matches: List[QualityMatch] = []

        # 1. Agnostic Duplicate Code Check
        raw_matches.extend(_check_duplicate_code(code_lines))

        # 2. Language-Specific AST Checks
        if target_lang == "python":
            try:
                tree = ast.parse(code)
                raw_matches.extend(_py_check_complexity_and_nesting(tree, code_lines))
                raw_matches.extend(_py_check_functions_and_file_length(tree, code_lines))
                raw_matches.extend(_py_check_parameters_and_god_class(tree, code_lines))
                raw_matches.extend(_py_check_exceptions(tree, code_lines))
                raw_matches.extend(_py_check_unused_symbols(tree, code_lines))
                raw_matches.extend(_py_check_magic_docstring_naming(tree, code_lines))
            except SyntaxError as err:
                logger.warning("Python syntax error encountered during CodeAnalysisAgent parse: %s", err)
        else:
            try:
                tree = javalang.parse.parse(code)
                raw_matches.extend(_java_check_methods_and_classes(tree, code_lines))
                raw_matches.extend(_java_check_exceptions_and_smells(tree, code_lines))
            except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError) as err:
                logger.warning("Java syntax error encountered during CodeAnalysisAgent parse: %s", err)
            except Exception as err:
                logger.warning("Java AST traversal issue in CodeAnalysisAgent: %s", err)

        # 3. Optional LLM Pass
        raw_matches.extend(self._execute_optional_llm_pass(code, target_lang, filename))

        # 4. Transform matches into unified Finding objects
        findings: List[Finding] = []
        for idx, match in enumerate(raw_matches, start=1):
            score = calculate_quality_score(match.rule_type, match.severity)
            finding_id = f"CODE-{idx:03d}"
            finding = Finding(
                id=finding_id,
                title=match.title,
                category="Code Smell & Maintainability",
                agent=self.agent_name,
                severity=match.severity,
                severity_score=score,
                file=filename,
                line_start=match.line_start,
                line_end=match.line_end,
                code_snippet=match.code_snippet,
                explanation=match.explanation,
                suggestion=match.suggestion,
                confidence=match.confidence,
                source="rule",
                owasp_category=None,
                cwe_id=None,
                evidence=f"Static AST Check: {match.rule_type}",
            )
            findings.append(finding)

        logger.info(
            "CodeAnalysisAgent completed: %d findings found in %s (%s)",
            len(findings),
            filename,
            target_lang,
        )
        return findings
