# Quality Validation and CI Reference

Read this reference when defining Make targets, aggregate validation, CI behavior, or debugging quality failures.

## Makefile interface

Prefer stable public targets:

```text
make fix
make check
make verify
make ci
```

### make fix

Mutating local normalization:

- formatter write mode;
- safe lint auto-fix;
- import normalization.

It must not intentionally change business behavior, run destructive migrations, or silently apply unsafe rewrites.

### make check

Fast read-only validation, commonly:

- lint;
- format check;
- static types;
- unit tests.

It must not modify tracked source files.

### make verify

Broader read-only/local verification when justified, such as:

- integration tests;
- build checks;
- Docker/Compose validation;
- selected E2E.

### make ci

Full non-mutating CI validation suitable for GitHub Actions.

Component Makefiles should expose equivalent concepts where practical; a root Makefile may delegate to backend/frontend targets.

## Changed-scope optimization

During development, fix/check only the affected component when supported.

Before final commit, run root `make fix` when cheap/deterministic, followed by the appropriate broad read-only target.

Do not run unrelated expensive suites merely because another component was formatted.

## Compact output

Suppress routine success noise while retaining diagnostics.

Make recipes may use `@` where appropriate to avoid echoing long command lines.

On failure, increase verbosity only for the failing command and only as much as needed.

## CI is read-only

Normal CI must not run write modes such as:

- `ruff check --fix`;
- `ruff format` write mode;
- `eslint --fix`;
- `prettier --write`.

CI verifies committed normalized state and fails when normalization is missing.

## Aggregate-check deduplication

Understand what aggregate targets already include.

Do not run full suites independently and immediately rerun them through an aggregate target.

Use:

```text
make fix
-> changed/new targeted typechecks/tests
-> targeted corrections
-> make check once
-> make verify only when justified
```

If `make verify` already includes `make check`, run only the necessary broad target unless a prior fast check is useful for failure isolation.

Project Makefiles/AGENTS should document aggregate coverage clearly enough that Codex does not discover it through repeated execution.

A full suite should normally run only once per validation level in a stabilized task.
