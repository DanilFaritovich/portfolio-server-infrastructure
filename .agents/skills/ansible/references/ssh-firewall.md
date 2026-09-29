# SSH and Firewall Safety

Read for any change to SSH authentication, listening ports, systemd socket activation, host firewall, or network access policy.

## Establish the current state

- Inspect the effective daemon configuration, enabled services, listening ports, firewall rules, and provider-side network controls. Distinguish `sshd` configuration from systemd `ssh.socket` listeners; socket activation may own the listening port on some Ubuntu installations.
- Confirm the **current** authorized SSH route from the controller and an independent recovery channel before any access-changing operation.
- Preserve existing accounts, ports, and rules unless their removal has been specifically approved.

## Safe staged changes

- Add an allow rule for the existing SSH port *before* enabling an inbound-deny firewall. Open only other ports actually required by deployed services.
- Use idempotent Ansible modules (for example `community.general.ufw` when this collection is selected and installed), not an uncontrolled series of shell commands.
- Check rendered SSH configuration with `sshd -t` or the supported host equivalent **before** applying it.
- When socket activation is active, ensure intended port changes are reflected in the effective socket listeners, not just in `sshd_config`. Validate the resulting listeners after any approved reload.
- Reload the narrowly affected service/socket only when needed; do not reboot as a shortcut.
- Verify a fresh SSH connection and required sudo access before disabling a fallback user, password authentication, or an existing port.
- If the connection drops or verification fails, stop. Use the preplanned recovery procedure; do not blindly retry SSH changes.

## CI and review

- CI may check template rendering and Ansible/YAML syntax against placeholders; it must not connect to the production host.
- Document any expected change to effective ports, access policy, recovery procedure, and external-provider dependencies in the PR.
- `--check` and `--diff` are not substitutes for actual port/firewall/SSH verification. They may require host contact and always need approval against production.
