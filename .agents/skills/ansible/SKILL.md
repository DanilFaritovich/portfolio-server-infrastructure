---
name: ansible
description: Safe, idempotent Linux host provisioning with Ansible; use for inventories, playbooks, roles, SSH, firewall, Docker host preparation, and validation. Load topic references only as needed.
---

# Ansible Infrastructure Standard

Use for Infrastructure as Code that configures Linux hosts. This skill governs Ansible implementation, not application packaging or release delivery.

## Core invariants

- Keep the controller (Ansible installation, working copy, private SSH key) separate from managed hosts. Do not install Ansible on hosts unless the project explicitly requires it.
- Use an inventory, small entry-point playbooks, and roles when their reuse/complexity warrants them. Do not create empty directories, placeholder roles, or speculative resources.
- Prefer idempotent modules from `ansible.builtin` or a justified installed collection over `shell`/`command`. For unavoidable commands, define accurate `changed_when` and error behavior instead of reporting unconditional changes.
- Preserve existing host configuration and unrelated changes. Make package, file, service, user, and network changes explicit and reviewable.
- Parameterize host names, addresses, ports, SSH users, networking, and versions. Do not hardcode one operator's machine or provider into reusable standards.
- Use handlers for service reload/restart only when managed configuration changes. Validate configuration before activation where supported.
- Use `become` only for tasks requiring elevated privileges; avoid leaking credentials via command arguments, environment, task output, or registered results.

## Production boundary

- Repository preparation, lint, syntax validation, and static review are permitted without touching a host.
- Never contact, gather facts from, ping, or execute a playbook against a live production host without explicit approval for that specific operation. This includes `--check`, `--diff`, and read-only ad-hoc Ansible commands.
- Never assume permission to deploy, reset, reboot, alter SSH/firewall, or remove resources from a generic "implement the playbook" request.
- Do not run production provisioning from PR/feature-branch CI. Keep CI non-mutating and independent of production credentials.
- Before an approved disruptive operation, plan a recovery path (provider console, verified alternate SSH session, backup/snapshot as appropriate); never treat Git branch deletion as a host rollback.
- Never disable the currently working SSH login or enable a blocking firewall before verified replacement access exists. Stop and ask when recovery cannot be demonstrated.

## Credentials, inventory, and output

- Commit safe inventory examples, not live production inventories or secrets. Never commit real passwords, tokens, private SSH keys, production env files, or operator SSH public keys by default.
- Obtain authorized public keys at execution time from an approved local source or secret-management mechanism; never fetch or transmit a private key to a managed host.
- Use Ansible Vault only when the project needs encrypted secrets in version control. Do not add Vault or a secrets manager solely to bootstrap a non-secret project.
- Protect sensitive tasks with narrowly scoped `no_log: true`; do not disable failure reporting globally. Apply appropriate permissions to files created on hosts.
- Prefer summary-first output, targeted validation, and small excerpts of failures. Follow the existing task-development-workflow context-efficiency and code-quality rules; do not create a second generic token-efficiency skill for Ansible.

## Topic routing

Read a reference only when its subject is in scope:

- [references/bootstrap.md](./references/bootstrap.md): initial controller access, managed administrator, sudo, and SSH public-key provisioning.
- [references/ssh-firewall.md](./references/ssh-firewall.md): SSH daemon/socket, access restrictions, firewall, and lockout prevention.
- [references/docker-host.md](./references/docker-host.md): Docker Engine, Compose plugin, host networks, and permission boundaries.
- [references/validation.md](./references/validation.md): Makefile/CI checks, live dry runs, structured failure diagnosis, and output limits.

When application containers or release workflows are in scope, also select the existing `docker` or `continuous-delivery` skill respectively. Do not copy their normative rules into this skill.

## Execution workflow

```text
inspect local project + current host-access contract
-> define scope and affected hosts
-> implement focused changes
-> safe local normalization where available
-> targeted offline validation
-> one aggregate local check
-> review diff, safety, inventory and secret boundaries
-> commit / push task branch / PR / CI
-> developer review
-> explicit authorization for any live-host action
```

A valid playbook is not proof of a successful live deployment. Report static verification, approved dry-run results, and actual host verification separately.
