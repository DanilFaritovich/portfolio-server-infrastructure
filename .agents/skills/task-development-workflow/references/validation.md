# Validation Reference

Read this reference when implementation changes behavior, tests, lint/type configuration, build behavior, integration boundaries, operator entry-points, or CI.

## Tests

When behavior changes, add or update the smallest meaningful tests.

Use:

- unit tests for isolated business logic;
- integration tests for repositories, databases, APIs, filesystems, or framework boundaries;
- E2E tests only for important complete scenarios.

For bug fixes, prefer:

```text
regression test
-> reproduce when practical
-> fix
-> rerun the regression test
```

Do not add tests only to increase count or coverage.

## Validate the public/operator path

When users are expected to invoke a stable wrapper such as a Make target, CLI command, setup script, migration command, or deployment entry-point, validate that wrapper as a product surface rather than validating only the lower-level command it calls.

Examples:

```text
documented: make setup
test:       make/setup orchestration with isolated fixtures
not only:   underlying pip/uv/ansible subcommand

documented: make bootstrap
test:       wrapper preflight/arguments/failure boundaries offline
live:       only after separate explicit authorization
```

A wrapper that passes unit tests but still requires undocumented manual prerequisites is not a complete operator experience. Prefer regression coverage for fresh-machine/fresh-config behavior, repeat execution, preservation of existing user configuration, and actionable prerequisite failures when those are part of the feature.

Keep local/offline validation distinct from entry-points that contact external or production systems. A command named `verify`, `smoke`, or `check` is not automatically safe/offline; follow its documented behavior.

## Normalize before read-only validation

Before lint/format/type/test validation, run the project's safe deterministic auto-fix for the affected scope.

Preferred interface:

```text
make fix
```

or a component equivalent.

Typical safe fixes include formatter write mode, safe lint auto-fixes, and import normalization.

Do not run a formatter/linter check first merely to discover issues the configured fix command is expected to correct.

Type checkers and tests are validation tools, not generic auto-fixers.

## Targeted development loop

Run the smallest check capable of confirming the current change:

- one test/test file;
- one affected package;
- lint/typecheck for changed files/component;
- backend-only or frontend-only checks.

Preferred loop:

```text
edit
-> targeted check
-> targeted correction
-> targeted check
```

Do not start with the complete CI pipeline.

## Validation deduplication

Know what aggregate targets already include.

Do not run a complete suite immediately before an aggregate target that runs the same suite again.

Examples:

- if `make check` includes all unit tests, use only changed/new targeted unit tests during implementation;
- if `make verify` includes all integration/E2E tests, do not run those complete suites separately immediately beforehand;
- if `make verify` already includes `make check`, do not run both at the final broad stage unless failure isolation justifies it.

Preferred final plan:

```text
make fix
-> changed/new targeted checks
-> make check once
-> make verify once only when justified
-> infrastructure smoke only when required and not already covered
```

Do not trade correctness for fewer checks; remove redundant coverage, not independent validation.

## Failure handling

When an optional execution worker is available and a failure is likely to produce large
logs or a repeated mechanical diagnose/fix/rerun loop, the whole bounded loop may be
delegated according to the context-efficiency reference. Keep behavioral/design decisions
and final acceptance on the primary model.

When a broad check fails:

1. identify the specific failure;
2. make the smallest correction;
3. rerun only the relevant failing scope;
4. return to the broad check only after the targeted issue is resolved.

Avoid:

```text
make ci -> fix -> make ci -> fix -> make ci
```

Do not rerun a successful check unless later changes could affect it.

When a developer supplies output from a manual/live run, use that evidence to diagnose and add regression coverage without automatically repeating the external action. Clearly distinguish developer-reported evidence from actions the agent itself executed.

## Standard targets

`make check` is the normal fast project validation and should usually cover lint, format validation, static types, and unit tests.

`make verify` is broader and should run only when justified by the task. It may include integration tests, E2E, builds, Docker/config validation, or explicitly documented live verification. Inspect its semantics before running it.

`make ci` is primarily for GitHub Actions and should not normally be the local debugging loop.

Expected split for ordinary software projects:

```text
local:  make fix -> targeted checks -> make check -> optional make verify
remote: push -> GitHub Actions -> make ci
```

Infrastructure projects may define additional LIVE targets; those remain outside the default offline sequence and require their own approval boundary.
