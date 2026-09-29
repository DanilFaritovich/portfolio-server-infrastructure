# Bootstrap a Managed Administrator

Read when initially provisioning an Ansible control account or migrating access away from root.

## Preflight

- Confirm the operator already has a working, authorized SSH session and access to the provider console or equivalent recovery channel.
- Inspect the actual connection contract (controller's SSH configuration, supported port, SSH daemon/socket, Python availability, sudo policy). Never assume port 22, a particular distro package state, or the presence of passwordless sudo.
- Use a separate bootstrap entry-point with the existing authorized account. Do not make the steady-state inventory depend on a user that has not yet been created.

## Account and key

- Create the chosen control account with `ansible.builtin.user` and an explicitly managed home/shell.
- Read only the **public** SSH key from an operator-approved local source at playbook execution time. For example, the controller may pass a local `.pub` path or its key content through an explicitly documented runtime variable. Do not include the actual key bytes in examples, commits, CI artifacts, chat transcripts, or task output.
- Manage `~/.ssh/authorized_keys` with `ansible.posix.authorized_key` (declare the `ansible.posix` dependency when used) or another appropriate module. Do not edit a private key.
- Protect home, `.ssh`, and authorized-key file permissions without overwriting unrelated authorized access.
- Make the choice of privilege model explicit. Passwordless unrestricted `sudo` is root-equivalent: enable it only when required and approved by project policy; otherwise use a deliberately scoped sudo policy or approved interactive elevation.
- Validate sudoers fragments with `visudo` before writing/activating them. Do not replace the system-wide sudoers file.

## Two-stage handoff

1. Bootstrap with the currently working account; do not change root-login or password-login settings here.
2. Open an independent SSH session using the new account and verify effective privilege escalation. Test the account through Ansible as a separate step.
3. Only after successful verification consider an independently reviewed SSH-hardening task. Keep existing fallback access until that task is proven safe.
4. Never claim bootstrap success based solely on an Ansible recap if the new login or its intended sudo path was not tested.

A `--check` run may not create the account and therefore cannot validate its subsequent SSH login. Document this limitation.
