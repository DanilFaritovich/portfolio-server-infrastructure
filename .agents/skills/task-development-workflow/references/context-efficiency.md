# Context Efficiency Reference

Read this reference when a task involves a large repository, a continuation of existing work, large diffs, noisy CLI output, or noticeable context/token pressure.

## Repository inspection

Read the applicable `AGENTS.md` first and use it as the repository map.

Read `ARCHITECTURE.md` only when the task affects architecture, persistence, service communication, infrastructure, deployment, or external integrations.

Prefer:

```text
AGENTS.md
-> determine scope
-> search relevant symbols/paths
-> read only useful ranges
```

Search before reading large files. Prefer targeted discovery such as:

```text
rg -n "RelevantClass|relevant_setting|relevant_endpoint" affected/path
```

Do not use `rg -n "^"`, mass `cat`, or equivalent commands merely to dump complete files into context.

For large files, start with the relevant range and expand only when dependencies require it.

Use one file-listing/search pass where practical instead of repeatedly enumerating the repository.

## Do not reread successful edits

After a successful edit, assume the write was applied.

Do not automatically:

- reread the complete edited file;
- run repeated `cat`, `sed`, or searches only to confirm a write;
- inspect `git diff` after every small edit.

Preferred flow:

```text
read -> understand -> edit -> targeted validation
```

Reread only when:

- an edit failed or conflicted;
- validation requires inspection;
- the next edit depends on exact current contents;
- several edits interact;
- final review reveals something unexpected.

## Continuation baseline

When continuing an already-started task branch, treat the existing reviewed task state as the continuation baseline.

Focus inspection and final review on the delta introduced by the current continuation.

Revisit earlier task changes only when:

- they were not previously reviewed;
- new work interacts with them;
- validation indicates a problem there;
- the current delta cannot be understood safely without them.

Do not treat every continuation as a fresh full-repository audit.

## Command output discipline

Use the most compact tool-native output that preserves actionable failures.

Prefer:

- quiet/summary flags;
- short tracebacks;
- filtered or machine-readable output when smaller and still useful;
- scoped commands;
- concise success summaries.

Avoid by default:

- verbose/debug modes;
- full successful test output;
- full Docker/container logs;
- dependency-install progress;
- repeated command banners;
- large successful CI logs.

Examples:

```text
pytest -q --tb=short
git status --short
docker compose config -q
```

If compact output is insufficient after a failure, rerun only the failing command/scope with the minimum extra detail needed.

Do not request verbose output proactively.

## Optional delegated execution workers

When an optional execution-worker tool is available, use it when delegation is likely to
save substantial primary-model context while keeping the task bounded.

Good delegation targets include:

- failing test, build, Docker/Compose, or CI workflows with large/noisy output;
- repeated mechanical `run -> diagnose -> fix -> rerun` loops;
- broad routine repository searches whose useful result is a compact summary;
- GitHub/CI inspection where raw logs or many remote records would otherwise enter the
  primary-model context;
- repetitive local refactors where intended behavior is already unambiguous.

Prefer delegating the whole bounded execution loop rather than one tiny shell command at
a time.

Run small deterministic commands with compact output directly when worker overhead would
be larger than the result.

Keep these responsibilities on the primary model:

- architecture and module-boundary decisions;
- security decisions and secret handling;
- persistence and migration strategy;
- transaction/concurrency design;
- deployment design and production mutation;
- public contracts and ambiguous behavior;
- final diff/acceptance review;
- Git staging, commits, branch/ref mutation, push, PR delivery, and merge.

Follow the worker's own tool/server instructions and permission boundary. Do not send
production credentials, secrets, or unrelated repository data merely to enable
delegation.

A delegated inspect operation should return a compact actionable result rather than raw
logs. After a delegated fix operation, the primary model must inspect the resulting
working-tree status/diff before accepting or delivering the changes.

If the optional worker is unavailable, fails to initialize, or cannot safely perform the
task, continue directly with the normal workflow. Its absence is not a project failure
and must not trigger installation or configuration changes unless the user explicitly
requested them.

## Agent narration

Keep intermediate narration short and decision-oriented.

Report only:

- meaningful findings;
- plan/scope changes;
- failures and their causes;
- important validation results.

Do not restate every successful tool call or routine read/fetch/status result.

## Final diff budget

Do not inspect a full diff after every edit.

Start final review with compact metadata:

```text
git status --short
git diff --cached --check
git diff --cached --stat
git diff --cached --name-status
```

If the patch is modest, review it once in full.

If the patch is large:

- prioritize the current continuation delta when applicable;
- review targeted diffs by risk area;
- do not dump the whole patch into context;
- if output is truncated, inspect only missing/high-risk paths rather than repeating the full diff.

Typical risk areas:

- application/architecture;
- infrastructure/configuration;
- tests;
- security-sensitive code.

Documentation-only changes usually need only targeted review when relevant.
