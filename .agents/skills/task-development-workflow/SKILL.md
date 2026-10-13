---
name: task-development-workflow
description: Core development workflow with task branches created strictly from develop, local-only commits, opt-in documentation, and automatic ARCHITECTURE.md maintenance for material architecture changes.
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
- leave remote publication, Pull Requests, and merge to the developer unless explicitly requested.

## Core workflow

```text
inspect branch/worktree
-> resolve develop (create from main if missing) -> task branch FROM develop, or continue current task branch
-> determine scope and read relevant context
-> implement complete change
-> make fix / component fix
-> targeted validation
-> make check once
-> optional make verify
-> requested documentation; update existing ARCHITECTURE.md if architecture materially changes
-> final review
-> local commit
-> STOP (push/PR/merge only on explicit request)
```

## Explicit task stop points

The default delivery boundary is a local commit, not remote publication. Explicit user instructions can request an earlier stop or separately authorize a push/PR.

If the caller explicitly requests a staged workflow such as:

```text
implement only
-> developer reviews/runs checks
-> later request performs commit/PR
```

stop at the requested stage. In particular:

- do not run validation commands when the caller reserved validation for manual execution;
- do not contact external/live systems merely because later validation would normally do so;
- do not stage or commit if the caller reserved those steps; do not push, open a Pull Request, or wait on CI without an explicit request;
- still prepare the code/configuration/documented commands required for the developer's next manual step;
- report later workflow stages as pending rather than treating them as failed.

A later explicit request may resume from the verified working tree without restarting completed implementation work.

## Start safely

The **only base for new task branches is `develop`**. Never create a task branch directly from `main`, even when `main` is checked out. Do not treat `main` as a fallback development base.

Before editing:

1. Check the current branch, local/remote `develop` availability, and staged, unstaged, and untracked changes.
2. If already on a non-base task/development branch, **continue there**; do not automatically create another branch or rebase/switch it.
3. If on `develop`, create a descriptive task branch from the current `develop` tip before editing.
4. If on `main`: use an existing local `develop` (or materialize a local tracking `develop` from `origin/develop`, when only the remote exists); then create the task branch **from `develop`**. If no local or remote `develop` exists, create **local `develop` from `main` first**, then create the task branch from that new `develop`. Never push the newly created `develop` implicitly.
5. Preserve all unrelated changes; if switching branches would overwrite work, stop and ask rather than forcing checkout, stashing, resetting, rebasing, or discarding it. Do not silently update or rewrite existing branches.
6. On detached HEAD, ambiguous/unrelated branches, or unresolved base state, ask before modifying files.

Never perform normal task development directly on `develop` or `main`; task commits remain local unless remote delivery was explicitly requested.

## Load only relevant context

Read project-local `AGENTS.md` first.

Read `ARCHITECTURE.md` only when the task affects architecture, persistence, service communication, infrastructure, deployment, or external integrations.

Inspect only relevant source, tests, interfaces, configuration, analogous implementations, and documentation.

For large repositories, continuations, noisy commands, large diffs, or optional delegated
execution workers, read [references/context-efficiency.md](./references/context-efficiency.md).

An execution worker is an optional capability, not a project dependency. When
`codex-free-worker-mcp` is available, prefer its `inspect_task` for bounded
high-output inspection/diagnostics and `fix_task` for unambiguous mechanical
diagnose/fix/rerun loops when delegation will materially reduce primary-model context.
Follow [references/context-efficiency.md](./references/context-efficiency.md) for routing
and safety boundaries. If that MCP is unavailable, continue directly without treating
that as an error or changing the project to install/configure it.

## Determine and implement scope

Before editing, identify:

- required behavior;
- affected components/files;
- existing tests;
- relevant project conventions;
- whether documentation was explicitly requested, or existing `ARCHITECTURE.md` must be updated because the task materially changes the architecture.

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

Do **not** create, update, or refresh routine documentation without an explicit request (including a request to synchronize agent standards/instructions). **Exception:** if implementation materially changes architecture—module/component responsibilities, boundaries/dependencies, major data or control flows, persistence/integration contracts, or deployment topology—make a minimal accurate update to an **existing** `ARCHITECTURE.md` after implementation stabilizes, even without a separate documentation request. Small refactors, file moves without changed responsibilities, and implementation details alone do not trigger this exception. Do not auto-create `ARCHITECTURE.md`, rewrite unrelated sections, or use the exception to change README/`docs/`/`AGENTS.md`.

Use the documentation skill for details.

## Final review

Start with compact status/diff metadata.

Do not dump a large full patch into context. Use targeted risk-area review when the patch is large.

For detailed context/diff rules, read [references/context-efficiency.md](./references/context-efficiency.md).

## Git delivery

When starting/continuing branches, committing, pushing, preparing PRs, or handling CI, read [references/git-delivery.md](./references/git-delivery.md).

Normal local endpoint:

```text
task branch -> validated changes -> local commit -> STOP
```

Stage only task-related files. **Do not push, create/update a Pull Request, or merge without a specific explicit user request.** An explicit request to create a PR also authorizes pushing its task branch, but not a merge. For requested remote delivery, target the configured development branch (normally `develop`).

## Completion criteria

For a normal task with local-only delivery, completion means:

- requested scope is implemented;
- required tests are updated;
- relevant targeted checks pass;
- the normal project check passes;
- extended verification was used when justified;
- final review is complete;
- documentation was changed only when explicitly requested, except minimal updates to existing `ARCHITECTURE.md` for material architecture changes;
- task changes are locally committed;
- push/PR/merge were not performed without explicit user authorization.

When the caller defines an earlier or later explicit stop point, complete only those authorized stages and report remaining delivery as pending.

Keep the final report concise; report results/status, not a chronological tool log.
