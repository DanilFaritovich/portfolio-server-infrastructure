# Ansible Validation and Output Discipline

Read when defining Make targets, CI, check mode, tests, or diagnosing an Ansible execution failure.

## Stable commands and offline checks

Prefer the project's existing Makefile interface:

```text
make fix      # optional: safe, deterministic local normalization only
make check    # fast, read-only validation
make verify   # optional broader local/disposable-environment checks
make ci       # non-mutating GitHub Actions validation
```

- Use `yamllint`, `ansible-lint`, `ansible-playbook --syntax-check`, and `actionlint` when their corresponding files or workflow are present.
- Declare/pin the required tool versions and Ansible collections as appropriate; ensure CI uses the same commands as local development.
- Run syntax checks with safe example/test inventory, not a live production inventory or credential. Syntax validation should not need SSH access.
- Never use `ansible-lint --fix` or broad rewrites blindly. If a safe fix mode exists, apply it only to intended files, inspect its diff, then run read-only validation.
- Avoid a fake `make fix` target that silently reports successful formatting while doing nothing. Document when no safe automatic fixer is configured.
- Validate YAML syntax, playbook syntax, lint, dependency declaration, and relevant templating/role behavior. Use a disposable VM/container for optional integration testing where reasonable; do not present such tests as production verification.

## Run discipline and recap

- During editing, run only changed-scope checks; after stabilizing changes, run the aggregate check once. Do not run overlapping complete suites twice.
- For `ansible-playbook` success, prefer a compact `PLAY RECAP` plus essential changed/failure status. Avoid verbose task dumps, unnecessary `-vvv`, repeated fact dumps, debug-var output, and whole remote log retrieval.
- Prefer documented, version-compatible callback/display configuration to reduce successful `ok`/`skipped` noise. Do not invent unsupported command flags, strip nonzero exit codes, hide `failed`/`unreachable` events, or suppress security warnings.
- On failure, investigate the failing host/task and minimum useful surrounding context; increase verbosity only for that isolated failure, never for the entire fleet by default.
- Never echo secrets while diagnosing failures; apply narrowly scoped `no_log` to sensitive operations. If capturing a log, keep it local, access-restricted, and ignored by Git, and sanitize any excerpt.

## Check mode, tests, and approval

- `--check --diff` may be a useful approved preflight but is incomplete: some modules do not support it, and simulated user/package changes may cause later tasks to fail or skip.
- Neither check mode nor `ansible -m ping` is inherently offline; both can contact a host. Require separate explicit permission when the target is production.
- A real run requires a named target, reviewed scope, a verified recovery path for disruptive changes, and explicit user approval.
- After a live run, verify the intended state and access from a separate session; do not equate `failed=0` with successful SSH, sudo, firewall, or container reachability.
