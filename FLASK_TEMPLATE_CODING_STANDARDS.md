# Flask Template Coding Standards

## 1. Indentation and Formatting

- Use four spaces for indentation in templates.
- Ensure consistent formatting across templates.
- Use whitespace for better readability, such as around control structures and filters.

## 2. Naming Conventions

- Use meaningful names for template variables.
- Avoid single-letter variable names unless used in short loops.
- Use underscores for variable names (e.g., `user_profile`, not `userProfile`).
- Use kebab-case for template names (e.g., `my-template-name-.html`) not otherwise.

## 3. Comments

- Include comments for complex logic or non-obvious template code.
- Begin comments with `{#` and end with `#}` for multiline comments.
- Keep comments concise and to the point.

## 4. Code Organization

- Organize templates logically based on functionality.
- Use template inheritance to promote code reuse.
- Separate concerns by dividing templates into smaller, focused files.
- Place commonly used macros in dedicated files for re-usability.

## 5. Styling

- Use consistent styling for HTML elements.
- Prefer class selectors over inline styles for better maintainability.
- Minimize the use of inline JavaScript and CSS.

## 6. Inclusion of External Resources

- Include external resources (CSS, JavaScript) with appropriate tags.
- Prefer using Flask's `url_for` for generating URLs to ensure flexibility.

## 7. Error Handling

- Implement error handling in templates when applicable.
- Provide informative error messages for users in case of template errors.