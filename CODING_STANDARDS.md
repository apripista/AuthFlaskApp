# Coding Standards

## 1. Indentation and Formatting

- Use 4 spaces for indentation.
- Ensure consistent formatting across the codebase.
- Avoid mixing spaces and tabs for indentation.
- Set your code editor to display spaces, making indentation more visible.
- Keep lines within a reasonable length (e.g., 80-120 characters) for readability.
- Ensure proper spacing around operators to enhance code clarity.

## 2. Naming Conventions

- Use CamelCase for class names.
- Use snake_case for function and variable names.
- Use SCREAMING_SNAKE_CASE for constants.
- Prefix private variables and functions with an underscore (e.g., `_my_private_variable`).
- Avoid single-letter variable names unless used in short loops (e.g., `for i in range(10):`).

## 3. Comments

- Include comments for complex or non-obvious code sections.
- Begin comments with a space after the `#` to enhance readability.
- Use clear and concise language in comments.
- Avoid redundant or obvious comments.
- Comment important decisions, assumptions, or potential pitfalls.
- Keep comments up-to-date with code changes.

## 4. Code Structure

- Organize code into logical modules and packages.
- Follow a consistent file structure.
- Group related functions and classes together.
- Avoid overly long functions; consider breaking them into smaller, focused functions.
- Separate concerns by adhering to the Single Responsibility Principle.
- Use meaningful and descriptive names for modules, directories, and files.

## 5. Imports

- Group imports in the following order: standard library, third-party, local.
- Use explicit import statements.
- Avoid using wildcard imports (`from module import *`).

## 6. Error Handling

- Handle errors gracefully and provide meaningful error messages.
- Avoid using bare `except` clauses; be specific about the exceptions you catch.
- Log errors for debugging purposes, providing additional context.

## 7. Testing

- Write tests for all new features and bug fixes.
- Ensure tests cover edge cases.
- Use meaningful names for test functions.
- Structure tests logically, separating setup, execution, and assertion phases.
- Run tests regularly to ensure ongoing code quality.