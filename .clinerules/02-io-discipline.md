# File I/O Discipline & Tool Usage

## Principles

- Never overwrite files blindly.
- Always read the file first, evaluate intent, and write the minimal diff.
- Preserve formatting, comments, and non-relevant sections.

## Tool Policy

- Default to using the `filesystem` MCP tool for **all file operations**:
  - Editing code
  - Reading content
  - Scanning directories
  - Refactoring or renaming across files
- The `filesystem` tool provides broader context and precise control over multi-file projects.

## Example Scenarios

- ✅ Use `filesystem`:
  - “Replace all imports of `old-util` with `new-util`”
  - “Update function signatures in every file under `/src/hooks/`”
