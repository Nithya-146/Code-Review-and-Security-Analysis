"""
Unit tests for CodeAnalysisAgent (Step 1).

Tests all rule-based checks across Python (ast) and Java (javalang):
1. Cyclomatic complexity per function/method
2. Long functions and long files
3. Deep nesting
4. Too many parameters
5. God class (too many methods or lines)
6. Duplicate code blocks
7. Bare or overly broad except/catch
8. Unused variables and imports
9. Magic numbers, missing docstrings/Javadoc, poor naming
10. Clean code samples producing zero findings (Python and Java)
11. Safe rules-only fallback when no LLM API key is present
"""

import pytest

from agents.code_analysis import (
    CodeAnalysisAgent,
    MAX_COMPLEXITY,
    MAX_FUNCTION_LINES,
    MAX_FILE_LINES,
    MAX_NESTING_DEPTH,
    MAX_PARAMETERS,
    MAX_CLASS_METHODS,
    MAX_CLASS_LINES,
    calculate_quality_score,
)
from app.schemas import SeverityLevel


@pytest.fixture
def agent() -> CodeAnalysisAgent:
    """Fixture providing a fresh CodeAnalysisAgent instance."""
    return CodeAnalysisAgent()


# ==============================================================================
# 1. Cyclomatic Complexity Tests
# ==============================================================================
def test_python_cyclomatic_complexity(agent: CodeAnalysisAgent):
    """Verifies detection of high cyclomatic complexity in Python."""
    code = '''
"""Module docstring."""

def highly_complex_function(x: int) -> int:
    """Calculates branch-heavy computation."""
    if x > 1:
        x += 1
    if x > 2:
        x += 2
    if x > 3:
        x += 3
    if x > 4:
        x += 4
    if x > 5:
        x += 5
    if x > 6:
        x += 6
    if x > 7:
        x += 7
    if x > 8:
        x += 8
    if x > 9:
        x += 9
    if x > 10:
        x += 10
    if x > 11:
        x += 11
    return x
'''
    findings = agent.run(code, language="python", filename="complex.py")
    complexity_findings = [f for f in findings if "Complexity" in f.title]
    assert len(complexity_findings) >= 1
    assert complexity_findings[0].severity in (SeverityLevel.HIGH, SeverityLevel.MEDIUM)
    assert complexity_findings[0].severity_score >= 7.0


def test_java_cyclomatic_complexity(agent: CodeAnalysisAgent):
    """Verifies detection of high cyclomatic complexity in Java."""
    code = """
/**
 * Math service class.
 */
public class MathService {
    /**
     * Highly branched method.
     */
    public int compute(int input_val) {
        int result = input_val;
        if (result > 1) { result += 1; }
        if (result > 2) { result += 2; }
        if (result > 3) { result += 3; }
        if (result > 4) { result += 4; }
        if (result > 5) { result += 5; }
        if (result > 6) { result += 6; }
        if (result > 7) { result += 7; }
        if (result > 8) { result += 8; }
        if (result > 9) { result += 9; }
        if (result > 10) { result += 10; }
        if (result > 11) { result += 11; }
        return result;
    }
}
"""
    findings = agent.run(code, language="java", filename="MathService.java")
    complexity_findings = [f for f in findings if "Complexity" in f.title]
    assert len(complexity_findings) >= 1
    assert complexity_findings[0].severity in (SeverityLevel.HIGH, SeverityLevel.MEDIUM)


# ==============================================================================
# 2. Long Functions and Long Files Tests
# ==============================================================================
def test_python_long_function_and_file(agent: CodeAnalysisAgent):
    """Verifies detection of long functions and long files in Python."""
    # Build a function with > 55 lines
    lines = ['"""Module doc."""', 'def very_long_function():', '    """Docstring."""', '    total = 0']
    for idx in range(55):
        lines.append(f'    total += {idx}')
    lines.append('    return total')
    code = "\n".join(lines)

    findings = agent.run(code, language="python", filename="long_func.py")
    long_func_findings = [f for f in findings if "Long Function" in f.title]
    assert len(long_func_findings) == 1
    assert long_func_findings[0].severity == SeverityLevel.MEDIUM

    # Test file > 300 lines
    file_lines = ['"""Big module."""'] + [f'# comment line {i}' for i in range(305)]
    big_file_code = "\n".join(file_lines)
    big_findings = agent.run(big_file_code, language="python", filename="big_file.py")
    assert any("Long File" in f.title for f in big_findings)


def test_java_long_function_and_file(agent: CodeAnalysisAgent):
    """Verifies detection of long methods and long files in Java."""
    lines = [
        "/** Class doc */",
        "public class LongClass {",
        "    /** Method doc */",
        "    public void longMethod() {",
        "        int counter = 0;",
    ]
    for idx in range(55):
        lines.append(f"        counter += {idx};")
    lines.append("    }")
    lines.append("}")
    code = "\n".join(lines)

    findings = agent.run(code, language="java", filename="LongClass.java")
    long_method_findings = [f for f in findings if "Long Method" in f.title]
    assert len(long_method_findings) == 1


# ==============================================================================
# 3. Deep Nesting Tests
# ==============================================================================
def test_python_deep_nesting(agent: CodeAnalysisAgent):
    """Verifies detection of deep indentation/nesting in Python."""
    code = '''
"""Module doc."""

def deeply_nested_function(data_val: int) -> None:
    """Processes nested structures."""
    if data_val > 0:
        for idx in range(10):
            while data_val < 5:
                if idx % 2 == 0:
                    if data_val == 1:
                        print("Deeply nested branch")
'''
    findings = agent.run(code, language="python", filename="nested.py")
    nesting_findings = [f for f in findings if "Deep" in f.title]
    assert len(nesting_findings) >= 1
    assert nesting_findings[0].severity == SeverityLevel.MEDIUM


def test_java_deep_nesting(agent: CodeAnalysisAgent):
    """Verifies detection of deep control flow nesting in Java."""
    code = """
/**
 * Processor class.
 */
public class Processor {
    /**
     * Deeply nested method.
     */
    public void process(int num) {
        if (num > 0) {
            for (int i = 0; i < 10; i++) {
                while (num < 5) {
                    if (num % 2 == 0) {
                        if (num == 1) {
                            System.out.println("Deeply nested Java");
                        }
                    }
                }
            }
        }
    }
}
"""
    findings = agent.run(code, language="java", filename="Processor.java")
    nesting_findings = [f for f in findings if "Deep" in f.title]
    assert len(nesting_findings) >= 1


# ==============================================================================
# 4. Too Many Parameters Tests
# ==============================================================================
def test_python_too_many_parameters(agent: CodeAnalysisAgent):
    """Verifies detection of functions with more than 5 parameters in Python."""
    code = '''
"""Module doc."""

def configure_service(host_name, port_number, timeout_sec, retry_count, enable_ssl, auth_token):
    """Initializes service connection."""
    return host_name
'''
    findings = agent.run(code, language="python", filename="params.py")
    param_findings = [f for f in findings if "Parameters" in f.title]
    assert len(param_findings) == 1
    assert param_findings[0].severity == SeverityLevel.MEDIUM


def test_java_too_many_parameters(agent: CodeAnalysisAgent):
    """Verifies detection of methods with more than 5 parameters in Java."""
    code = """
/**
 * Connection manager.
 */
public class ConnectionManager {
    /**
     * Connects with many params.
     */
    public void connect(String host, int port, int timeout, int retries, boolean ssl, String token) {
        System.out.println(host);
    }
}
"""
    findings = agent.run(code, language="java", filename="ConnectionManager.java")
    param_findings = [f for f in findings if "Parameters" in f.title]
    assert len(param_findings) == 1


# ==============================================================================
# 5. God Class Tests
# ==============================================================================
def test_python_god_class(agent: CodeAnalysisAgent):
    """Verifies detection of a God Class (> 10 methods) in Python."""
    methods = [f'    def method_{i}(self):\n        """Doc."""\n        return {i}' for i in range(12)]
    code = '"""Module doc."""\n\nclass KitchenSinkGodClass:\n    """Huge class."""\n' + "\n".join(methods)
    findings = agent.run(code, language="python", filename="god_class.py")
    god_findings = [f for f in findings if "God Class" in f.title]
    assert len(god_findings) == 1
    assert god_findings[0].severity == SeverityLevel.HIGH


def test_java_god_class(agent: CodeAnalysisAgent):
    """Verifies detection of a God Class (> 10 methods) in Java."""
    methods = [f"    /** Doc {i} */\n    public void method{i}() {{ }}" for i in range(12)]
    code = "/** God Class */\npublic class GodService {\n" + "\n".join(methods) + "\n}"
    findings = agent.run(code, language="java", filename="GodService.java")
    god_findings = [f for f in findings if "God Class" in f.title]
    assert len(god_findings) == 1


# ==============================================================================
# 6. Duplicate Code Blocks Tests
# ==============================================================================
def test_duplicate_code_blocks(agent: CodeAnalysisAgent):
    """Verifies detection of duplicate code blocks (>= 6 lines)."""
    block = """
    alpha_value = 10
    beta_value = 20
    gamma_value = 30
    delta_value = 40
    epsilon_value = 50
    zeta_value = 60
"""
    code = f'''
"""Module doc."""

def first_routine():
    """First routine."""
{block}
    return alpha_value

def second_routine():
    """Second routine."""
{block}
    return beta_value
'''
    findings = agent.run(code, language="python", filename="duplicates.py")
    dup_findings = [f for f in findings if "Duplicate" in f.title]
    assert len(dup_findings) >= 1
    assert dup_findings[0].severity == SeverityLevel.MEDIUM


# ==============================================================================
# 7. Bare and Broad Exception Catch Tests
# ==============================================================================
def test_python_bare_and_broad_exceptions(agent: CodeAnalysisAgent):
    """Verifies detection of bare except: and broad except Exception: in Python."""
    code = '''
"""Module doc."""

def risky_operations():
    """Demonstrates bad error handling."""
    try:
        val = 1 / 0
    except:
        val = 0

    try:
        val2 = 2 / 0
    except Exception:
        val2 = 1
    return val + val2
'''
    findings = agent.run(code, language="python", filename="exceptions.py")
    exc_findings = [f for f in findings if "Except" in f.title]
    assert len(exc_findings) == 2
    titles = [f.title for f in exc_findings]
    assert any("Bare" in t for t in titles)
    assert any("Broad" in t for t in titles)


def test_java_broad_catch(agent: CodeAnalysisAgent):
    """Verifies detection of catch (Exception e) in Java."""
    code = """
/**
 * Exception handler demo.
 */
public class ExceptionDemo {
    /**
     * Executes work.
     */
    public void runWork() {
        try {
            int division = 10 / 0;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
"""
    findings = agent.run(code, language="java", filename="ExceptionDemo.java")
    exc_findings = [f for f in findings if "Catch" in f.title or "Exception" in f.title]
    assert len(exc_findings) >= 1
    assert exc_findings[0].severity == SeverityLevel.MEDIUM


# ==============================================================================
# 8. Unused Variables and Imports Tests
# ==============================================================================
def test_python_unused_imports_and_variables(agent: CodeAnalysisAgent):
    """Verifies detection of unused imports and unread local variables in Python."""
    code = '''
"""Module doc."""
import math
import sys

def calculate_something():
    """Performs computation."""
    unused_number = 42
    used_number = 10
    return used_number + math.sqrt(used_number)
'''
    findings = agent.run(code, language="python", filename="unused.py")
    unused_imports = [f for f in findings if "Unused Import" in f.title]
    unused_vars = [f for f in findings if "Unused Local Variable" in f.title]
    assert len(unused_imports) >= 1
    assert "sys" in unused_imports[0].explanation
    assert len(unused_vars) >= 1
    assert "unused_number" in unused_vars[0].explanation


def test_java_unused_imports(agent: CodeAnalysisAgent):
    """Verifies detection of unused imports in Java."""
    code = """
package com.demo;
import java.util.List;
import java.util.ArrayList;

/**
 * Demo class.
 */
public class ImportDemo {
    /**
     * Uses list.
     */
    public void demo() {
        List<String> items = null;
    }
}
"""
    findings = agent.run(code, language="java", filename="ImportDemo.java")
    unused_imports = [f for f in findings if "Unused Import" in f.title]
    assert len(unused_imports) >= 1
    assert "ArrayList" in unused_imports[0].explanation


# ==============================================================================
# 9. Magic Numbers, Missing Docstrings, Poor Naming Tests
# ==============================================================================
def test_python_magic_numbers_and_naming(agent: CodeAnalysisAgent):
    """Verifies detection of magic numbers, missing docstrings, and poor naming."""
    code = """
def f(x):
    y = 999
    return x + y
"""
    findings = agent.run(code, language="python", filename="smells.py")
    titles = [f.title for f in findings]
    assert any("Magic Number" in t for t in titles)
    assert any("Docstring" in t for t in titles)
    assert any("Naming" in t for t in titles)


def test_java_magic_numbers_and_naming(agent: CodeAnalysisAgent):
    """Verifies detection of magic numbers and missing Javadoc in Java."""
    code = """
public class MagicDemo {
    public void compute() {
        int magicVal = 888;
    }
}
"""
    findings = agent.run(code, language="java", filename="MagicDemo.java")
    titles = [f.title for f in findings]
    assert any("Magic Number" in t for t in titles)
    assert any("Javadoc" in t for t in titles)


# ==============================================================================
# 10. Clean Code Samples (Must Produce Zero Findings)
# ==============================================================================
def test_clean_python_code_produces_zero_findings(agent: CodeAnalysisAgent):
    """Verifies that clean, idiomatic Python code triggers zero code quality findings."""
    clean_code = '''"""
Clean and well-documented payment processor service.
"""

MAX_RETRIES: int = 3


class PaymentService:
    """Manages transactional customer charges and refunds."""

    def __init__(self, service_name: str) -> None:
        """Initializes payment service instance."""
        self.service_name = service_name

    def process_charge(self, account_identifier: str, amount_cents: int) -> bool:
        """
        Processes an individual payment charge for a customer.

        Args:
            account_identifier: Target customer account ID.
            amount_cents: Charge value in integer cents.

        Returns:
            True if payment was authorized successfully.
        """
        if amount_cents <= 0:
            return False

        try:
            return self._execute_gateway_request(account_identifier, amount_cents)
        except ValueError as err:
            return False

    def _execute_gateway_request(self, account_id: str, total_cents: int) -> bool:
        """Simulates internal gateway interaction."""
        for _ in range(MAX_RETRIES):
            if total_cents > 0 and len(account_id) > 1:
                return True
        return False
'''
    findings = agent.run(clean_code, language="python", filename="clean_service.py")
    assert findings == [], f"Expected 0 findings on clean Python sample, got: {[f.title for f in findings]}"


def test_clean_java_code_produces_zero_findings(agent: CodeAnalysisAgent):
    """Verifies that clean, idiomatic Java code triggers zero code quality findings."""
    clean_java = """package com.example.service;

/**
 * Clean enterprise payment processing service.
 */
public class CleanPaymentProcessor {

    /**
     * Maximum retry limit constant.
     */
    public static final int MAX_ATTEMPTS = 3;

    /**
     * Processes customer transaction.
     *
     * @param accountId Customer account identifier.
     * @param chargeAmount Transaction amount in dollars.
     * @return True if successful.
     */
    public boolean processTransaction(String accountId, int chargeAmount) {
        if (chargeAmount <= 0) {
            return false;
        }

        try {
            return executeTransaction(accountId, chargeAmount);
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    /**
     * Internal payment gateway execution.
     *
     * @param account Target account id.
     * @param amount Target charge amount.
     * @return Result of the operation.
     */
    private boolean executeTransaction(String account, int amount) {
        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            if (amount > 0 && account.length() > 1) {
                return true;
            }
        }
        return false;
    }
}
"""
    findings = agent.run(clean_java, language="java", filename="CleanPaymentProcessor.java")
    assert findings == [], f"Expected 0 findings on clean Java sample, got: {[f.title for f in findings]}"


# ==============================================================================
# 11. Configuration & Rules-Only Fallback Tests
# ==============================================================================
def test_rules_only_fallback_without_llm_api_key(agent: CodeAnalysisAgent, monkeypatch):
    """Verifies that without an API key, CodeAnalysisAgent runs cleanly in rules-only mode."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setenv("LLM_PROVIDER", "none")

    code = '"""Simple module."""\ndef demo():\n    """Doc."""\n    return 1\n'
    findings = agent.run(code, language="python", filename="demo.py")
    assert isinstance(findings, list)


def test_scoring_function():
    """Verifies that quality defect scoring matches documented tiers."""
    assert calculate_quality_score("god_class", SeverityLevel.HIGH) == 8.0
    assert calculate_quality_score("cyclomatic_complexity", SeverityLevel.HIGH) == 7.5
    assert calculate_quality_score("deep_nesting", SeverityLevel.MEDIUM) == 6.0
    assert calculate_quality_score("magic_number", SeverityLevel.LOW) == 2.0
    assert calculate_quality_score("unknown_rule", SeverityLevel.INFO) == 1.0
