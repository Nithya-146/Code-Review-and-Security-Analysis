import javalang
from typing import Dict, Any, List

def validate_java(code: str) -> Dict[str, Any]:
    """
    Parses Java source code using javalang to verify syntax
    and extracts declared classes and methods.
    """
    if not code.strip():
        return {
            "is_valid": False,
            "error": "Submission is empty. Please provide Java code.",
            "metadata": {}
        }

    try:
        tokens = javalang.tokenizer.tokenize(code)
        parser = javalang.parser.Parser(tokens)
        tree = parser.parse()
        
        classes: List[str] = []
        methods: List[str] = []
        
        for _, node in tree.filter(javalang.tree.ClassDeclaration):
            classes.append(node.name)
            
        for _, node in tree.filter(javalang.tree.MethodDeclaration):
            methods.append(node.name)

        return {
            "is_valid": True,
            "error": None,
            "metadata": {
                "classes": classes,
                "methods": methods,
                "lines_of_code": len(code.splitlines())
            }
        }
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError) as e:
        return {
            "is_valid": False,
            "error": f"Java Syntax Error: {str(e)}",
            "metadata": {}
        }
    except Exception as e:
        return {
            "is_valid": False,
            "error": f"Java Parsing Failed: {str(e)}",
            "metadata": {}
        }