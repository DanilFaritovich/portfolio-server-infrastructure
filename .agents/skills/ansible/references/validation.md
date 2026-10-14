# Ansible Validation and Output Discipline

Read when defining Make targets, CI, check mode, tests, or diagnosing an Ansible execution failure.

## Stable commands and offline checks

Prefer the project's existing Makefile interface:

```text
make fix      # optional: safe, deterministic local normalization only
make check    # fast, read-only/offline validation
make verify   # semantics must be documented; may be local OR explicitly LIVE
make ci       # non-mutating GitHub Actions validation
```

- Use `yamllint`, `ansible-lint`, `ansible-playbook --syntax-check`, and `actionlint` when their corresponding files or workflow are present.
- Declare/pin the required tool versions and Ansible collections as appropriate; ensure CI uses the same commands as local development.
- Run syntax checks with safe example/test inventory, not a live production inventory or credential. Syntax validation should not need SSH access.
- Never use `ansible-lint --fix` or broad rewrites blindly. If a safe fix mode exists, apply it only to intended files, inspect its diff, then run read-only validation.
- Avoid a fake `make fix` target that silently reports successful formatting while doing nothing. Document when no safe automatic fixer is configured.
- Validate YAML syntax, playbook syntax, lint, dependency declaration, relevant templating/role behavior, and operator wrappers when those wrappers are part of the public workflow.
- Use a disposable VM/container for optional integration testing where reasonable; do not present such tests as production verification.

Do not assume `make verify` is offline merely because of its name. If a project defines it as a production SSH/Ansible verification target, label it LIVE in documentation/output and require explicit approval before running it.

## Operator-path regression coverage

When a repository exposes convenience entry-points such as `make setup`, `make bootstrap`, or `make verify`, test the same orchestration that operators will use instead of validating only raw underlying commands.

Offline tests should cover important wrapper boundaries with synthetic fixtures/mocks as appropriate:

- fresh and repeated setup;
- preservation of existing local configuration/inventory;
- missing/incompatible controller prerequisites;
- generated-key path/permission handling without exposing private-key contents;
- first-use host trust confirmation/rejection/failure;
- connection transport selection and credential-free child arguments/environment;
- controller-local tasks remaining local when remote connection overrides exist;
- cleanup of temporary files/overlays;
- expected stop behavior before any live mutation when preflight fails.

These tests do not replace a separately authorized live run, but they should catch controller orchestration bugs before production contact.

## Run discipline and recap

- During editing, run only changed-scope checks; after stabilizing changes, run the aggregate check once. Do not run overlapping complete suites twice.
- For `ansible-playbook` success, prefer a compact `PLAY RECAP` plus essential changed/failure status. Avoid verbose task dumps, unnecessary `-vvv`, repeated fact dumps, debug-var output, and whole remote log retrieval.
- Prefer documented, version-compatible callback/display configuration to reduce successful `ok`/`skipped` noise. Do not invent unsupported command flags, strip nonzero exit codes, hide `failed`/`unreachable` events, or suppress security warnings.
- Fix warnings caused by project-owned environment/configuration instead of hiding them. For known third-party deprecation noise with no compatible fix, use the narrowest possible suppression and keep real Ansible/security warnings enabled.
- On failure, investigate the failing host/task and minimum useful surrounding context; increase verbosity only for that isolated failure, never for the entire fleet by default.
- Never echo secrets while diagnosing failures; apply narrowly scoped `no_log` to sensitive operations. If capturing a log, keep it local, access-restricted, and ignored by Git, and sanitize any excerpt.

## Check mode, live verification, and approval

- `--check --diff` may be a useful approved preflight but is incomplete: some modules do not support it, and simulated user/package changes may cause later tasks to fail or skip.
- Neither check mode nor `ansible -m ping` is inherently offline; both can contact a host. Require separate explicit permission when the target is production.
- A real run requires a named target, reviewed scope, a verified recovery path for disruptive changes, and explicit user approval.
- A bootstrap recap with `failed=0` is not sufficient. Verify the intended new login and privilege path through an independent connection.
- A repeat bootstrap used to prove `changed=0` is another live mutating operation, not an offline test; require explicit authorization and report it separately.
- Distinguish agent-executed live evidence from developer-reported evidence. Do not imply Codex performed a production action it only reviewed from supplied output.
