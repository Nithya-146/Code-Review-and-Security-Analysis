import ast
from typing import Dict, Any, List

def validate_python(code: str) -> Dict[str, Any]:
    """
    Validates Python source code syntax using the standard ast library
    and extracts basic structural metadata.
    """
    try:
        parsed_tree = ast.parse(code)
        
        functions: List[str] = []
        classes: List[str] = []
        imports: List[str] = []
        
        for node in ast.walk(parsed_tree):
            if isinstance(node, ast.FunctionDef):
                functions.append(node.name)
            elif isinstance(node, ast.ClassDef):
                classes.append(node.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)

        return {
            "is_valid": True,
            "error": None,
            "metadata": {
                "functions": functions,
                "classes": classes,
                "imports": imports,
                "lines_of_code": len(code.splitlines())
            }
        }
    except SyntaxError as err:
        return {
            "is_valid": False,
            "error": f"SyntaxError at line {err.lineno}, column {err.offset}: {err.msg}",
            "metadata": {}
        }