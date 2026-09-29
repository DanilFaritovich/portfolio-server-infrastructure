# Repository Instructions

This repository is for Ansible-based provisioning of a personal portfolio VPS. The intended target is an Ubuntu host; Docker and GitHub Actions are part of the planned stack. No provisioning implementation or validation commands exist yet.

- Use `develop` as the base for task branches and open Pull Requests into `develop`. Do not merge without an explicit request.
- Keep Ansible changes idempotent and reviewable. Use built-in modules where practical, parameterize host-specific values, and limit privilege escalation to tasks that need it.
- Do not contact a live host, including Ansible `--check`, without explicit approval for that operation. CI must use offline checks and must not contact production.
- Do not read, commit, or expose real inventories, private keys, passwords, tokens, or other secrets. Preserve the existing `LICENSE`.
- Load only the applicable core skill from `.agents/skills/` and its topic references when needed. Follow `.codex-standards.lock.yaml` and the `standards-sync` skill for future updates.
