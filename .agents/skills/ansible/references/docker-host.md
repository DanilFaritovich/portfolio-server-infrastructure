# Docker Host Provisioning

Read when the task installs or maintains Docker on a Linux host; use the existing `docker` skill for container/Compose application design.

## Host packages and services

- Detect the actual OS release, architecture, existing Docker/container packages, and repository configuration before selecting an installation method.
- Prefer supported vendor packages/repositories and explicitly managed signing configuration. Avoid unaudited `curl | sh` installations and unexpected replacement of an existing runtime.
- Manage Docker Engine and the Compose plugin via idempotent package and service tasks. Avoid unnecessary service restarts, package upgrades, and reboots.
- Pin major versions or precise package versions when the target's reproducibility and update policy require them; do not silently install unbounded updates during an unrelated task.

## Privilege and network boundaries

- Docker socket access / membership in the `docker` group is effectively root-level privilege. Require an explicit access-policy decision; do not put every account in the group automatically.
- Keep server-wide Docker resources such as a shared external network owned by host-infrastructure Ansible when that is the declared contract.
- Application repositories may attach to an existing external network; they should not silently recreate or delete host-owned infrastructure.
- Do not build or deploy unrelated application images while implementing the Docker-host role.
- Keep the reverse proxy, application CI/CD, database state, and secret provisioning in their designated owners.

## Validation

- Validate package/repository configuration without mutating production from CI.
- After separately authorized live execution, verify daemon and Compose availability, expected network presence, and actual command privileges.
- Use concise status/recap output on success; inspect only the failed step/service on failure.
