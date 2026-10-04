# Bootstrap a Managed Administrator

Read when initially provisioning an Ansible control account or migrating access away from root.

## Scope and stop boundary

Treat bootstrap as a narrow transition from an already working administrative SSH path to a dedicated managed automation account.

Normal bootstrap scope:

```text
existing authorized SSH account
-> bootstrap entry-point
-> managed automation account
-> controller-provided public key
-> sudo policy
-> stop for independent login/privilege verification
```

Do not bundle Docker installation, application deployment, reverse-proxy configuration, firewall enablement, SSH-port changes, root-login removal, password-authentication changes, or other hardening into this bootstrap unless the task explicitly requests that additional scope. A successful bootstrap does not authorize those later stages.

If the caller asks only for implementation/preparation, create the repository files and stop at that requested boundary. Do not contact a live host, run checks, or perform Git delivery when the task explicitly reserves those actions for the developer.

## Preflight

- Confirm the operator already has a working, authorized SSH session and access to the provider console or equivalent recovery channel before any separately approved live bootstrap.
- Inspect the actual connection contract (controller's SSH configuration, supported port, SSH daemon/socket, Python availability, sudo policy). Never assume port 22, a particular distro package state, or the presence of passwordless sudo.
- Use a separate bootstrap entry-point with the existing authorized account. Do not make the steady-state inventory depend on a user that has not yet been created.
- Fail early on missing required controller inputs, especially the public-key source, before making account/sudo changes where practical.

## Recommended project shape

Keep the bootstrap implementation small and explicit. A typical project may use:

```text
ansible.cfg
inventories/
  production.example.yml
playbooks/
  bootstrap.yml
roles/
  bootstrap_user/
    defaults/main.yml
    tasks/main.yml
requirements.yml
```

Names may differ to match project conventions; do not create empty placeholder directories or speculative roles.

- Commit only a safe example inventory with documentation placeholders.
- Keep the real production inventory local/ignored when it contains host-specific access data that the project does not intentionally publish.
- Parameterize the initial SSH user, host, port, managed automation username, and public-key source instead of embedding one operator's environment in reusable tasks.
- Keep the bootstrap playbook as a small entry point and put reusable account/bootstrap behavior in a role when that improves clarity.

## Account and controller-side key

- Create the chosen control account with `ansible.builtin.user` and an explicitly managed home/shell. `ansible` is a conventional account name, not a required hardcoded value.
- Read only the **public** SSH key from an operator-approved local source at playbook execution time. Prefer an explicit controller-side variable such as a local `.pub` path or public-key content supplied at runtime.
- Resolve/read a path-based public key on the Ansible controller, not on the not-yet-configured remote account. Validate that the required input is present/readable and fail clearly when it is not.
- Never read, copy, upload, or print the corresponding private key. Do not include actual key bytes in examples, commits, CI artifacts, chat transcripts, or task output.
- Manage `~/.ssh/authorized_keys` with `ansible.posix.authorized_key` (declare the `ansible.posix` dependency when used) or another appropriate idempotent module. Do not use `echo >> authorized_keys`.
- Protect home, `.ssh`, and authorized-key ownership/permissions without overwriting unrelated authorized access.

## Sudo policy

- Make the privilege model explicit. A dedicated automation account commonly needs non-interactive `become`; unrestricted `NOPASSWD` sudo is root-equivalent and must be a deliberate project-policy choice, not an accidental default.
- Prefer a dedicated fragment such as `/etc/sudoers.d/<managed-user>` rather than modifying `/etc/sudoers` directly.
- Manage the fragment idempotently with root ownership and restrictive permissions (normally `0440`).
- Validate the candidate sudoers fragment with `visudo -cf` through the module's validation mechanism before activation. Never install an unvalidated sudoers fragment.
- Do not use `chmod 777`, shell append hacks, or privilege-bypass workarounds.

## Idempotency and local validation contract

- Re-running bootstrap against an already-correct host should report the account, key, and sudo state as unchanged.
- Prefer purpose-built Ansible modules to `shell`/`command`.
- When project validation is in scope, expose stable offline checks through the repository's Makefile and validation standard: YAML lint, Ansible lint, syntax checks with safe example/test inventory, and workflow validation when applicable.
- Offline validation must not contact production, use a production private key, or depend on production credentials.
- When the task explicitly says the developer will run validation manually, prepare these commands/configuration but do not execute them.

## Two-stage handoff

1. Bootstrap with the currently working account; do not change root-login or password-login settings here.
2. Stop and open an independent SSH session using the new account; verify its intended privilege escalation separately.
3. Test the account through Ansible as a separate live step only after explicit authorization for that host contact.
4. Only after successful verification consider an independently reviewed SSH-hardening/firewall task. Keep existing fallback access until that task is proven safe.
5. Never claim bootstrap success based solely on an Ansible recap if the new login or its intended sudo path was not tested.

A `--check` run may not create the account and therefore cannot validate its subsequent SSH login. Document this limitation.
