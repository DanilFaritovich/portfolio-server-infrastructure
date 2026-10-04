# Repository Instructions

This repository is for Ansible-based provisioning of a personal portfolio VPS on Ubuntu. The current implementation only bootstraps a managed automation user through existing administrative access. Later provisioning stages require separate tasks.

- `playbooks/bootstrap.yml` calls `roles/bootstrap_user`; `inventories/production.example.yml` is the only committed inventory. Actual inventories remain local and ignored.
- `make deps` installs pinned controller tooling/collections from registries. `make check` and `make ci` run YAML lint, offline Ansible lint, syntax validation with example inventory, and actionlint. Neither contacts production. No safe automatic fixer or broader integration target is configured.
- See `README.md` for the manual bootstrap and independent SSH/sudo handoff. A successful recap is not verification of new access.

- Use `develop` as the base for task branches and open Pull Requests into `develop`. Do not merge without an explicit request.
- Keep Ansible changes idempotent and reviewable. Use built-in modules where practical, parameterize host-specific values, and limit privilege escalation to tasks that need it.
- Do not contact a live host, including Ansible `--check`, without explicit approval for that operation. CI must use offline checks and must not contact production.
- Do not read, commit, or expose real inventories, private keys, passwords, tokens, or other secrets. Preserve the existing `LICENSE`.
- Load only the applicable core skill from `.agents/skills/` and its topic references when needed. Follow `.codex-standards.lock.yaml` and the `standards-sync` skill for future updates.
