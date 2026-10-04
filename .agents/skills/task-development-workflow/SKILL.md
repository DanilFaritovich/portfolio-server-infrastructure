---
name: task-development-workflow
description: Core workflow for implementing one software development task with Codex, from scoped context and implementation through validation, documentation, commit, Pull Request, and CI. Load references only when their topic applies.
---

# Task Development Workflow

Use this core workflow for normal feature, fix, refactor, chore, and documentation tasks unless project-local instructions are stricter.

## Core goals

- implement the complete requested scope;
- read only context required for the task;
- preserve unrelated user changes;
- follow existing architecture and conventions;
- normalize before read-only validation;
- use targeted checks during development;
- use an available optional execution worker for bounded high-output or mechanical loops
  when delegation clearly reduces primary-model context;
- avoid repeated reads/checks;
- leave final merge to the developer.

## Core workflow

```text
inspect branch/worktree
-> determine scope
-> read only relevant project context
-> implement complete change
-> make fix / component fix
-> targeted validation
-> make check once
-> optional make verify
-> final review
-> update required docs
-> commit
-> push task branch
-> Pull Request
-> GitHub CI
-> developer review/merge
```

## Explicit task stop points

The core workflow is a default end-to-end path, not permission to ignore a narrower user-requested boundary.

If the caller explicitly requests a staged workflow such as:

```text
implement only
-> developer reviews/runs checks
-> later request performs commit/PR
```

stop at the requested stage. In particular:

- do not run validation commands when the caller reserved validation for manual execution;
- do not contact external/live systems merely because later validation would normally do so;
- do not stage, commit, push, open a Pull Request, or wait on CI when delivery was deferred;
- still prepare the code/configuration/documented commands required for the developer's next manual step;
- report later workflow stages as pending rather than treating them as failed.

A later explicit request may resume from the verified working tree without restarting completed implementation work.

## Start safely

Use the repository's configured development branch, normally `develop`.

Before editing:

1. check current branch and working tree;
2. preserve unrelated staged/unstaged/untracked changes;
3. create or continue a dedicated task branch;
4. never reset/revert unrelated work.

Do not perform normal task development directly in `develop` or `main`.

## Load only relevant context

Read project-local `AGENTS.md` first.

Read `ARCHITECTURE.md` only when the task affects architecture, persistence, service communication, infrastructure, deployment, or external integrations.

Inspect only relevant source, tests, interfaces, configuration, analogous implementations, and documentation.

For large repositories, continuations, noisy commands, large diffs, or optional delegated
execution workers, read [references/context-efficiency.md](./references/context-efficiency.md).

An execution worker is an optional capability, not a project dependency. Use it only when
it is available and its advertised tool/server instructions fit the bounded task. If it
is unavailable, continue directly without treating that as an error or changing the
project to install it.

## Determine and implement scope

Before editing, identify:

- required behavior;
- affected components/files;
- existing tests;
- relevant project conventions;
- documentation that may need a final update.

Avoid unrelated refactoring.

Implement every requirement in the requested scope and prefer existing patterns over parallel abstractions.

## Validation

When behavior, tests, build configuration, integration boundaries, or CI are affected, read [references/validation.md](./references/validation.md).

Default local sequence:

```text
implementation
-> safe deterministic fix
-> changed/new targeted checks
-> targeted corrections
-> make check once
-> make verify only when justified
```

Do not use the full CI pipeline as a normal debugging loop.

Do not repeat a successful check unless later changes could affect it.

## Documentation

Update documentation after implementation and necessary validation stabilize, not continuously while code is changing.

Use the documentation skill for detailed documentation rules.

## Final review

Start with compact status/diff metadata.

Do not dump a large full patch into context. Use targeted risk-area review when the patch is large.

For detailed context/diff rules, read [references/context-efficiency.md](./references/context-efficiency.md).

## Git delivery

When starting/continuing branches, committing, pushing, preparing PRs, or handling CI, read [references/git-delivery.md](./references/git-delivery.md).

Normal destination:

```text
task branch -> develop
```

Codex must not merge the Pull Request unless the user explicitly requests that separate action.

## Completion criteria

For a normal end-to-end task, completion means:

- requested scope is implemented;
- required tests are updated;
- relevant targeted checks pass;
- the normal project check passes;
- extended verification was used when justified;
- final review is complete;
- required documentation is current;
- task changes are committed/pushed;
- Pull Request is prepared;
- CI is running or complete.

When the caller defined an earlier explicit stop point, completion is scoped to that boundary: complete the requested stages, preserve the working state for continuation, and clearly list the intentionally pending validation/delivery stages.

Keep the final report concise; report results/status, not a chronological tool log.
