---
name: documentation
description: Project documentation conventions for English and Russian README files, component documentation, AGENTS.md, ARCHITECTURE.md, code comments, and updating docs only after implementation stabilizes.
---

# Documentation Standard

Documentation should describe the final, working state of the project.

Do not continuously rewrite documentation while implementation is still changing.

## Documentation timing

Update documentation after:

1. implementation is complete;
2. required tests are added or updated;
3. targeted checks pass;
4. the standard project check passes;
5. extended verification is complete when required;
6. the final implementation is stable.

Then synchronize the affected documentation before commit/push/PR.

## Supported README languages

During project initialization, determine the desired README language mode:

- English only;
- Russian only;
- English + Russian.

Preferred filenames:

### English only

`README.md`

### Russian only

`README.md`

GitHub renders `README.md` automatically, so a Russian-only repository may use Russian directly in the root README.

### English + Russian

```text
README.md
README.ru.md
```

Use:

- `README.md` — English;
- `README.ru.md` — Russian.

Add visible language links at the top of both files.

Both versions must describe the same project state.

## Root README

The root README is the primary entry point.

Document only relevant topics, such as:

- project purpose;
- features;
- architecture overview;
- technology stack;
- repository structure;
- requirements;
- installation;
- configuration;
- environment variables;
- development;
- testing;
- Makefile commands;
- Docker;
- database migrations;
- API;
- CI/CD;
- deployment;
- limitations;
- license.

Do not add empty sections merely because a template contains them.

## Component README files

Files such as:

- `backend/README.md`;
- `frontend/README.md`;

are optional.

Create them only when a component has enough independent setup, commands, architecture, or operational information to justify separate documentation.

Avoid duplicating the root README.

The root README should link to component documentation when it exists.

When bilingual component documentation is required, use the same language convention consistently.

## AGENTS.md

`AGENTS.md` is an agent-facing project map, not a duplicate README.

Keep it compact.

It should contain:

- project purpose;
- stack summary;
- important directories;
- architectural boundaries;
- development/test commands;
- project-specific rules;
- references to deeper documentation/skills.

Update it when project structure, important commands, or development rules change.

Do not force the agent to read every documentation file before every task.

## ARCHITECTURE.md

Use `ARCHITECTURE.md` for deeper architecture documentation:

- modules/components;
- responsibilities;
- dependency direction;
- important data flows;
- persistence;
- integrations;
- deployment topology;
- architectural decisions;
- important invariants and constraints.

Update it when architecture changes, not after every implementation detail.

## Code documentation

Developer-facing code documentation should be in English by default:

- docstrings;
- technical comments;
- public interface descriptions;
- internal developer explanations.

A repository may explicitly choose another convention, but keep it consistent.

Prefer comments that explain:

- why;
- invariants;
- constraints;
- non-obvious trade-offs;
- unusual behavior.

Do not comment obvious code line by line.

## API documentation

Keep generated API documentation accurate through:

- meaningful schemas;
- endpoint summaries/descriptions where useful;
- correct status codes;
- accurate request/response types.

Do not duplicate large README sections inside API descriptions.

## Documentation accuracy

Never document planned behavior as if it already exists.

If a feature is unfinished, label it clearly or omit it until implemented.

Commands shown in README should be real commands from the repository.

## Documentation review

Before a Pull Request:

- verify links;
- verify commands;
- remove stale instructions;
- ensure language versions stay aligned;
- ensure architecture descriptions match the actual implementation.

Do not rerun unrelated application tests solely because prose documentation changed after successful code validation, unless documentation generation itself is executable/validated.
