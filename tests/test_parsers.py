"""
Unit tests for Python and Java AST Parsers.
"""

from app.python_parser import validate_python
from app.java_parser import validate_java


def test_python_valid_syntax():
    code = """
import os
import sys

def calculate_metrics(values):
    return sum(values)

class MetricsCollector:
    pass
"""
    result = validate_python(code)
    assert result["is_valid"] is True
    assert result["error"] is None
    assert "calculate_metrics" in result["metadata"]["functions"]
    assert "MetricsCollector" in result["metadata"]["classes"]
    assert "os" in result["metadata"]["imports"]
    assert result["metadata"]["lines_of_code"] > 0


def test_python_syntax_error():
    broken_code = """
def unclosed_parenthesis(
    x = 10
"""
    result = validate_python(broken_code)
    assert result["is_valid"] is False
    assert result["error"] is not None
    assert "SyntaxError" in result["error"]


def test_java_valid_syntax():
    java_code = """
public class PaymentGateway {
    public void processPayment(double amount) {
        System.out.println("Payment processed: " + amount);
    }
}
"""
    result = validate_java(java_code)
    assert result["is_valid"] is True
    assert result["error"] is None
    assert "PaymentGateway" in result["metadata"]["classes"]
    assert "processPayment" in result["metadata"]["methods"]


def test_java_syntax_error():
    broken_java = """
public class BrokenSyntax {
    public void invalidMethod( {
}
"""
    result = validate_java(broken_java)
    assert result["is_valid"] is False
    assert result["error"] is not None
