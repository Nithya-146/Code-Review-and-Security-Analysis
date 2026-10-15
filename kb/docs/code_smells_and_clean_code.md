# Code Quality Smells and Best Practices Guide

## Overview
This document catalogs common code smells, anti-patterns, and clean code refactoring guidelines across Python and Java codebases.

## Top 10 Code Smells and Refactoring Techniques

### 1. Long Method
- **Problem**: A method or function contains too many lines of code, handles multiple responsibilities, and is difficult to comprehend or test.
- **Refactoring**: Extract Method. Break distinct logical blocks into smaller, single-purpose helper functions with descriptive names.

### 2. Large Class (God Class)
- **Problem**: A single class accumulates excessive responsibilities, state variables, and methods, violating the Single Responsibility Principle (SRP).
- **Refactoring**: Extract Class / Component. Separate concerns into cohesive domain services or helper classes.

### 3. Duplicate Code
- **Problem**: Identical or very similar code blocks duplicated across multiple locations. Bugs fixed in one location remain present in others.
- **Refactoring**: Pull Up Method, Extract Function, or create a shared utility module.

### 4. Long Parameter List
- **Problem**: Functions with 5+ parameters are fragile, prone to parameter ordering mistakes, and hard to read.
- **Refactoring**: Introduce Parameter Object (e.g., Pydantic model in Python, DTO or Builder in Java).

### 5. Deep Nesting
- **Problem**: Excessive indentation (nested if/else and loop blocks) creates high cyclomatic complexity and impairs readability.
- **Refactoring**: Use Guard Clauses and early returns (`return` / `continue` / `break`) to handle edge conditions upfront.

### 6. Magic Numbers and Strings
- **Problem**: Hardcoded literal values (numbers, magic status strings) scattered across the code without explanatory context.
- **Refactoring**: Replace with named constants or enumerations (`Enum` in Python/Java).

### 7. Dead Code
- **Problem**: Unused functions, unreachable branches, and commented-out legacy code that create noise and maintenance debt.
- **Refactoring**: Delete safely. Rely on version control history if old code is ever needed.

### 8. Feature Envy
- **Problem**: A method in one class excessively invokes accessors and manipulates data of another class rather than its own.
- **Refactoring**: Move Method. Place the behavior closer to the data it operates on.

### 9. Data Clumps
- **Problem**: Specific fields (e.g., `street`, `city`, `zip_code`, `state`) repeatedly passed together across function calls.
- **Refactoring**: Encapsulate into a dedicated value object or dataclass.

### 10. Primitive Obsession
- **Problem**: Relying solely on raw primitive types (`str`, `int`) for complex concepts like monetary amounts, email addresses, or phone numbers.
- **Refactoring**: Introduce small, strongly-typed domain primitives with built-in validation.
