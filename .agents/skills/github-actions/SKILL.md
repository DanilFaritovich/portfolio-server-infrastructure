---
name: github-actions
description: GitHub Actions CI conventions for Pull Request validation, Makefile-based checks, caching, full verification, branch integration, and keeping heavy CI work out of the normal local Codex debugging loop.
---

# GitHub Actions CI Standard

Use GitHub Actions as the final independent validation layer for Pull Requests.

Local development should stay targeted and efficient. CI may perform the broader and more expensive verification.

## Branch workflow

Default long-lived branches:

- `main` — stable branch;
- `develop` — active integration/development branch.

Task branches are created from `develop`, for example:

- `feature/...`
- `fix/...`
- `refactor/...`
- `chore/...`
- `docs/...`

Normal flow:

`develop -> task branch -> Pull Request -> develop`

Release flow:

`develop -> Pull Request -> main`

Do not use direct pushes to `main` for normal development.

Prefer Pull Requests for `develop` as well.

## CI triggers

At minimum, run CI for Pull Requests targeting:

- `develop`;
- `main`.

Optionally run CI on pushes to those branches when the project benefits from post-merge verification.

## Single command interface

Prefer a stable project-level command such as:

`make ci`

GitHub Actions should call the same public developer interface used by the repository rather than duplicating long command sequences in workflow YAML.

Typical workflow:

```text
checkout
-> setup runtimes
-> install/cache dependencies
-> make ci
```

## Separation of local and CI checks

Local Codex workflow:

```text
make fix
-> targeted checks
-> make check
-> optional make verify
```

CI workflow:

```text
make ci
```

Do not require Codex to repeatedly reproduce the entire CI pipeline locally.

## CI is read-only

GitHub Actions must verify the committed state, not repair it.

Do not run formatter/linter write modes in normal CI, including:

- `ruff check --fix`;
- `ruff format` in write mode;
- `eslint --fix`;
- `prettier --write`.

Use read-only validation instead:

- `ruff check`;
- `ruff format --check`;
- ESLint without `--fix`;
- `prettier --check`;
- mypy/pyright;
- tsc/vue-tsc;
- tests.

If CI fails on formatting or an auto-fixable lint issue, fix it in the task branch and push the corrected commit.

Do not allow CI to mutate tracked source files and then continue as if the repository itself were valid.

## CI scope

Depending on the project, `make ci` may include:

- backend lint;
- backend format validation;
- static type checking;
- frontend lint;
- frontend type checking;
- unit tests;
- integration tests;
- selected E2E tests;
- frontend production build;
- Docker/Compose validation;
- container builds;
- migrations/startup verification;
- health checks.

Do not add expensive checks that provide no meaningful protection.

## Failure handling

When CI fails:

1. identify the failing job/check;
2. inspect only the relevant logs;
3. reproduce the smallest useful failure locally when practical;
4. make a targeted fix;
5. run targeted validation;
6. rerun the relevant local project check if affected;
7. push;
8. let GitHub Actions rerun.

Do not feed large successful logs back into the agent.

Do not rerun unrelated local checks unless the fix can affect them.

## CI log volume

Keep successful CI output compact.

Prefer:

- quiet dependency installation where supported;
- concise test reporters;
- non-verbose lint/typecheck output;
- build summaries instead of full debug traces;
- focused log retrieval for failed services/steps.

Do not enable `--verbose`, debug logging, full container log dumps, or equivalent high-volume output by default.

When a job fails, inspect only the failing step and the minimum surrounding logs required to diagnose it.

If compact output is insufficient, increase verbosity only for that failing step.

## Caching

Use standard dependency caches when useful and simple.

Examples:

- pip/uv cache;
- npm/pnpm/yarn cache;
- Docker layer/build cache.

Do not add complex caching infrastructure before build time justifies it.

## Matrix builds

Use a matrix only when the project genuinely supports multiple required runtimes/platforms.

Do not multiply CI cost for combinations the project does not claim to support.

## CD gating

When GitHub Actions also performs production deployment, the deployed revision must first pass its required validation.

Do not structure independent push-triggered CI and deploy workflows so deployment can start while CI for the same commit is still running or can fail independently.

Prefer one of:

- a deployment job that `needs` the required validation/build jobs in the same workflow;
- a reusable validation workflow called by the deployment workflow;
- a carefully filtered `workflow_run`/equivalent gate that deploys only the exact successfully validated revision.

Branch protection before merge is useful but does not replace validation of the exact production revision when post-merge changes/checks can differ.

For workflow changes, provision and run deterministic workflow validation such as `actionlint`; do not silently skip the final check because the tool is unavailable locally.

## Required checks

For repositories that support branch protection/rulesets, configure required CI checks before merge into:

- `develop`;
- `main`.

If automation cannot change repository settings, document the required manual GitHub configuration.

## Security

Use GitHub Secrets / environment secrets for credentials.

Never commit:

- deployment credentials;
- API tokens;
- private keys;
- production passwords.

Limit workflow permissions to what jobs actually need.

Pin or deliberately version third-party actions rather than silently depending on unstable behavior.

## Pull Request responsibility boundary

CI validates changes.

Codex may prepare/create the PR, but must not merge automatically unless the user explicitly requests that separate action.

The developer owns the final review and merge decision.
