---
name: documentation
description: Opt-in project documentation, bilingual README standards and portfolio README badges/presentation, plus existing ARCHITECTURE.md maintenance for material changes.
---

# Documentation Standard

Documentation should describe the final, working state of the project.

**Default: do not create, edit, regenerate, or synchronize documentation unless explicitly requested.** This includes README files, `docs/`, `AGENTS.md`, API docs, changelogs, examples and documentation-only docstring rewrites. Feature/fix work, successful tests and planned commits do not implicitly authorize such edits.

**Narrow exception:** when the actual implementation materially changes the system architecture, update the relevant sections of an **existing `ARCHITECTURE.md`** automatically so future Codex work follows the true structure. This does not authorize creating that file if absent or modifying any other documentation.

An explicit request to write/update documentation or install/update project-local standards/instructions authorizes only the relevant documentation scope. Keep necessary code comments accurate during code changes without broad unsolicited documentation rewrites.

Do not continuously rewrite documentation while implementation is still changing.

## Documentation timing

For an **explicitly requested** documentation task, or an existing `ARCHITECTURE.md` update triggered by a material architecture change, update documentation after:

1. implementation is complete (if any);
2. required tests are added or updated;
3. targeted checks pass;
4. the standard project check passes;
5. extended verification is complete when required;
6. the final implementation is stable.

Before local commit, synchronize only the requested documentation or the minimal warranted `ARCHITECTURE.md` changes. Push/PR require separate explicit approval.

## Supported README languages

When README creation is explicitly requested during project initialization, determine the desired language mode:

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

For an **explicit user request** to create or redesign a README for a public/portfolio project, follow [the portfolio README presentation reference](./references/portfolio-readme.md). Read this reference **only** for that work; do not load it for normal coding, private/internal projects, or unrelated documentation changes. It defines a compact, verified top badge strip (actual stack, CI, license), presentation structure, technical detail boundaries, and bilingual parity. Match established repository style without adding irrelevant technologies, visuals, or claims.

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

Update it only when the user explicitly requests changes to project instructions (including requested standards installation or synchronization).

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

Update an **existing** `ARCHITECTURE.md` automatically when implementation materially changes one or more of:

- module/component responsibilities or architectural boundaries;
- dependency direction, interfaces or integration contracts;
- major data/control flows or persistence architecture;
- infrastructure/deployment topology or key architectural invariants.

Keep changes small and grounded in the final implementation. Do not update it for ordinary bug fixes, minor refactoring, formatting, or renames that do not change the architecture. If the file is absent, do not generate it without an explicit request. This exception never authorizes README, `docs/`, or `AGENTS.md` edits.

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

For explicitly requested documentation, before the local commit or an authorized Pull Request:

- verify links;
- verify commands;
- remove stale instructions;
- ensure language versions stay aligned;
- ensure architecture descriptions match the actual implementation;
- for requested portfolio README updates, verify every badge's technology/version, CI workflow, status, license, URL, image and alt text against the actual repository; do not show unsupported claims.

Do not rerun unrelated application tests solely because prose documentation changed after successful code validation, unless documentation generation itself is executable/validated.
