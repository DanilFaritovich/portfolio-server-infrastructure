---
name: code-quality
description: Core local quality workflow: safe deterministic auto-fix before targeted read-only validation, stable Make targets, deduplicated checks, and non-mutating CI. Load stack-specific references only when needed.
---

# Code Quality Standard

Normalize changed code before read-only quality validation.

The goal is to avoid predictable formatter/linter failures and repeated broad checks.

## Core workflow

```text
implementation
-> safe auto-fix
-> changed/new targeted type/tests
-> targeted corrections
-> make check once
-> optional make verify
```

Do not deliberately run a formatter/linter check first when the configured safe fix step can normalize the same code.

## Safe auto-fix

Preferred public interface:

```text
make fix
```

For monorepos, root `make fix` may delegate to backend/frontend component targets.

Safe fixes may include formatter write mode, safe lint auto-fixes, and import normalization.

Do not enable unsafe semantic rewrites merely to make checks pass.

Type checkers and tests are validation, not generic auto-fix tools.

## Stack-specific guidance

For Python/Ruff/mypy/pytest details, read [references/python.md](./references/python.md) only when Python quality tooling is affected.

For Vue/TypeScript/ESLint/Prettier/Vitest details, read [references/frontend.md](./references/frontend.md) only when frontend quality tooling is affected.

## Public Make targets

Projects using Makefiles should prefer:

```text
make fix
make check
make verify
make ci
```

Core meaning:

- `make fix`: mutating safe local normalization;
- `make check`: fast read-only validation;
- `make verify`: broader read-only verification when justified;
- `make ci`: full non-mutating CI validation.

Component Makefiles should expose equivalent concepts where practical.

For detailed target semantics, output rules, aggregate deduplication, and CI behavior, read [references/validation-and-ci.md](./references/validation-and-ci.md).

## Changed-scope optimization

During development, normalize and validate only the affected component/scope when supported.

Use changed/new targeted tests and type checks while editing.

Do not run unrelated expensive suites because another component changed formatting.

## Deduplicate validation

Know what aggregate targets already include.

Do not execute a full unit/integration/E2E suite immediately before an aggregate target that will rerun that same complete suite.

A full suite should normally run only once per validation level after the task stabilizes.

## CI rule

Normal CI is read-only.

CI verifies that committed code is already normalized; it must not silently fix source and continue.

## Completion

Code-quality validation is ready when:

- safe fixes were applied;
- changed files are normalized;
- targeted type/tests pass;
- the appropriate broad read-only target passes;
- broader verification runs only when justified;
- CI can verify the committed state without mutating it.
