"""
Planted Quality Smells Sample.
Contains intentional code quality defects for code_analysis agent.
"""


def complex_calculator(val: int) -> int:
    """Function with high cyclomatic complexity."""
    result = val
    if val > 0:
        result += 1
    if val > 1:
        result += 1
    if val > 2:
        result += 1
    if val == 0:
        result += 1
    if val == 1:
        result += 1
    if val == 2:
        result += 1
    if val == -1:
        result += 1
    if val == 100:
        result += 1
    if val != 0:
        result += 1
    if val != 1:
        result += 1
    if val != 2:
        result += 1
    return result


def deeply_nested_processor(items: list) -> None:
    """Function with deeply nested control flow blocks."""
    if items:
        for item in items:
            if item > 0:
                while item < 100:
                    if item % 2 == 0:
                        print(item)
                    item += 1


def exception_handling_sample() -> None:
    """Function with overly broad exception handler and magic number."""
    try:
        threshold = 42.5
        print(threshold)
    except Exception as err:
        print(f"Error occurred: {err}")
