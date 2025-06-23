# Cline Memory Bank Usage

## Purpose

- Maintain persistent project context across sessions.
- Store critical information such as goals, decisions, architecture, and progress.

## When to Use

- At the start of each session: Read all Memory Bank files to rebuild context.
- After significant changes: Update relevant Memory Bank files to reflect new information.
- When planning new features or refactoring: Document intentions and rationale.

## Memory Bank Structure

- Located in the `cline_docs/` directory at the project root.
- Core files include:
  - `projectbrief.md`: Overview of project goals and scope.
  - `productContext.md`: User needs and product requirements.
  - `systemPatterns.md`: Architectural decisions and design patterns.
  - `techContext.md`: Technologies used and technical constraints.
  - `activeContext.md`: Current focus, recent changes, and next steps.
  - `progress.md`: Status updates, completed tasks, and known issues.

## Memory-Bank discipline
1. ALWAYS consult files in cline_docs/ before starting a new task.
2. If required doc files are missing or incomplete, ask the user for info, THEN write the files via the filesystem-mcp tool before coding.
3. At the end of any task, update cline_docs/activeContext.md with:
   - Summary of what changed
   - Next clear action items

## Example Triggers

- "Initialize memory bank"
- "Update memory bank"
- "Refer to memory bank for project context"
