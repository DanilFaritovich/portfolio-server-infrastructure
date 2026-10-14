# Bootstrap a Managed Administrator

Read when initially provisioning an Ansible control account or migrating access away from root.

## Scope and stop boundary

Treat bootstrap as a narrow transition from a provider-issued administrative access path to a dedicated managed automation account. The initial path may be root/password, root/key, or a non-root administrator with sudo; do not assume one authentication mechanism.

Normal bootstrap scope:

```text
existing administrative access
-> explicit host trust
-> bootstrap entry-point
-> managed automation account
-> controller-managed public key
-> sudo policy
-> independent login/privilege verification
-> stop
```

Do not bundle Docker installation, application deployment, reverse-proxy configuration, firewall enablement, SSH-port changes, root-login removal, password-authentication changes, or other hardening into this bootstrap unless the task explicitly requests that additional scope. A successful bootstrap does not authorize those later stages.

If the caller asks only for implementation/preparation, create the repository files and stop at that requested boundary. Do not contact a live host, run live verification, or perform Git delivery when the task explicitly reserves those actions for the developer.

## Operator-facing workflow

Prefer a small, stable repository interface over long raw Ansible commands. For a reusable bootstrap project, a good operator path is conceptually:

```text
make setup
-> edit local inventory
-> make bootstrap
-> make verify
```

Names may differ to match project conventions, but the responsibilities should stay clear:

- setup is controller-local preparation only;
- bootstrap is LIVE/MUTATING and creates or repairs the managed automation access;
- verify is a separate live verification path and must not silently rerun the bootstrap role;
- offline checks remain distinct from both live targets.

When practical, setup should prepare pinned project-local tooling instead of requiring a specific system Python/runtime version. Do not silently install system packages with sudo. If a system prerequisite is genuinely required, fail early with a short actionable message. Setup should create a missing local production inventory from a safe example without overwriting an existing operator file.

Test the documented operator entry-points, not only their underlying raw commands. A repository that claims one-command setup/bootstrap should be exercised through those targets with offline mocks before live use.

## Preflight and first-use host trust

- Confirm the operator has provider-issued administrative credentials and access to the provider console or equivalent recovery channel before any separately approved live bootstrap.
- Inspect the actual connection contract (host, port, initial user, supported authentication, remote Python availability, sudo policy). Never assume port 22, a particular distro package state, passwordless sudo, or pre-existing key authentication.
- Do not require the operator to manually run a separate SSH command only to seed `known_hosts` when the bootstrap interface can safely handle first-use trust itself.
- For an unknown host, retrieve its public SSH host key, display the host/port, key type, and SHA256 fingerprint, explain that the network response alone does not prove identity, and require explicit interactive confirmation before saving trust. Encourage comparison against the provider console when available.
- Keep strict host-key checking enabled. Never silently trust a first-seen key, use `StrictHostKeyChecking=no`, or automatically replace a changed known-host key. A changed key is a hard stop requiring operator investigation.
- Complete host trust before prompting for an administrative password or making remote mutations.
- Use a separate bootstrap entry-point with the initial administrator. Do not make the steady-state inventory depend on a user that has not yet been created.

## Recommended project shape

Keep the bootstrap implementation small and explicit. A typical project may use:

```text
ansible.cfg
inventories/
  production.example.yml
playbooks/
  bootstrap.yml
  verify.yml
roles/
  bootstrap_user/
    defaults/main.yml
    tasks/main.yml
scripts/
  setup/bootstrap wrapper as needed
```

Names may differ to match project conventions; do not create empty placeholder directories or speculative roles.

- Commit only a safe example inventory with documentation placeholders.
- Keep the real production inventory local/ignored when it contains host-specific access data that the project does not intentionally publish.
- Parameterize the initial SSH user, host, port, managed automation username, and public-key source instead of embedding one operator's environment in reusable tasks.
- Keep the bootstrap playbook as a small entry point and put reusable account/bootstrap behavior in a role when that improves clarity.
- Keep runtime connection overrides scoped to the managed host. Do not pass remote `ansible_host`, connection type, or SSH transport settings as global extra-vars when controller-local/delegated tasks also run in the same play.

## Account and controller-side key

- Create the chosen control account with `ansible.builtin.user` and an explicitly managed home/shell. `ansible` is a conventional account name, not a required hardcoded value.
- A reusable bootstrap may generate or reuse a dedicated controller-side SSH key immediately before live bootstrap. Do not generate it during generic setup unless the project intentionally defines that behavior.
- Keep the private key outside the repository and under restrictive permissions. Never read, copy, upload, print, commit, or include its bytes in CI artifacts, chat transcripts, logs, or generated inventory.
- Send only the corresponding public key to the managed host. Validate the local `.pub` as a regular readable file before account/sudo mutations where practical.
- Resolve/read a path-based public key on the Ansible controller, not on the not-yet-configured remote account.
- Controller-side validation/read tasks must execute in an explicit local connection context and use the controller/playbook Python. Remote host/connection overrides must not leak into delegated localhost tasks.
- Manage `~/.ssh/authorized_keys` with `ansible.posix.authorized_key` (declare the `ansible.posix` dependency when used) or another appropriate idempotent module. Do not use `echo >> authorized_keys`.
- Protect home, `.ssh`, and authorized-key ownership/permissions without overwriting unrelated authorized access.

A key generated without a passphrase for unattended automation is a deliberate security trade-off. When it is combined with unrestricted `NOPASSWD` sudo, possession of that private key is effectively root-equivalent access; document and protect it accordingly.

## Initial password authentication

When the fresh-server path uses an initial SSH password:

- prompt interactively through the supported connection layer;
- never place the password in inventory, CLI arguments, environment variables, generated files, shell history, logs, or CI;
- prefer a supported project-local dependency/transport when that avoids forcing operators to install an extra system helper;
- do not hide system package installation inside setup;
- pin the chosen transport/dependency and add regression coverage for its effective authentication/host-key options;
- treat transport deprecations as compatibility work to fix, not warnings to globally suppress.

After bootstrap, steady-state verification/provisioning should prefer the dedicated key path rather than continuing to depend on the initial password.

## Sudo policy

- Make the privilege model explicit. A dedicated automation account commonly needs non-interactive `become`; unrestricted `NOPASSWD` sudo is root-equivalent and must be a deliberate project-policy choice, not an accidental default.
- Prefer a dedicated fragment such as `/etc/sudoers.d/<managed-user>` rather than modifying `/etc/sudoers` directly.
- Manage the fragment idempotently with root ownership and restrictive permissions (normally `0440`).
- Validate the candidate sudoers fragment with `visudo -cf` through the module's validation mechanism before activation. Never install an unvalidated sudoers fragment.
- Do not use `chmod 777`, shell append hacks, or privilege-bypass workarounds.

## Idempotency and local validation contract

- Re-running bootstrap against an already-correct host should report the account, key, and sudo state as unchanged.
- Prefer purpose-built Ansible modules to `shell`/`command`.
- When project validation is in scope, expose stable offline checks through the repository's Makefile and validation standard: YAML lint, Ansible lint, syntax checks with safe example/test inventory, wrapper/setup tests, and workflow validation when applicable.
- Offline tests should mock process/network boundaries so controller setup, first-use trust, password transport selection, local-key handling, connection scoping, and failure paths can be verified without contacting production.
- Offline validation must not contact production, use a production private key, or depend on production credentials.
- When the task explicitly says the developer will run validation manually, prepare these commands/configuration but do not execute them.
- Keep successful validation output concise. Fix project-owned warning causes instead of globally disabling warnings; narrowly suppress only understood third-party noise when no compatible fix exists.

## Live handoff and idempotency verification

Treat the live path as distinct approved operations:

1. Bootstrap with the initial administrative credential; do not change root-login or password-login settings here.
2. Stop the bootstrap connection and verify the new account through an independent key-only session.
3. Verify the intended non-interactive privilege path, for example `sudo -n`, separately from account creation.
4. Run the project's Ansible verification path as the managed account only after explicit authorization for that live host contact.
5. When live idempotency evidence is required, a second bootstrap run is another LIVE/MUTATING operation and requires its own authorization. An already-correct host should report `changed=0`.
6. Only after successful verification consider an independently reviewed SSH-hardening/firewall task. Keep existing fallback access until that task is proven safe.
7. Never claim bootstrap success based solely on an Ansible recap if the new login or intended sudo path was not tested.

A `--check` run may not create the account and therefore cannot validate its subsequent SSH login. Document this limitation.

Report offline validation, live bootstrap, independent verification, and optional live idempotency results separately. If the developer reports a live result that Codex did not execute, preserve that provenance instead of claiming the agent performed it.
