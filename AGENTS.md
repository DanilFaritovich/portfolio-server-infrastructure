# Repository Instructions

This repository is for Ansible-based provisioning of a personal portfolio VPS on Ubuntu. The current implementation only bootstraps a managed automation user through existing administrative access. Later provisioning stages require separate tasks.

- `playbooks/bootstrap.yml` calls `roles/bootstrap_user`; `inventories/production.example.yml` is the only committed inventory. Actual inventories remain local and ignored.
- `plugins/connection/portfolio_password.py` reuses pinned builtin Paramiko with direct plugin options for password-only bootstrap; verification still uses OpenSSH. Core 2.18.6 lacks variable bindings for key lookup/auto-add, so do not restore their deprecated environment/INI settings or suppress deprecation warnings.
- `make deps` uses `scripts/setup.sh` to prepare checksum-verified pinned local uv, managed Python 3.12 in `.tools/python`, `.venv`, and pinned tooling/collections from registries; no system Python or uv is required. `make check` and `make ci` run YAML lint, offline Ansible lint, syntax validation with example inventory, actionlint, and offline access/setup tests with synthetic fixtures and mocked commands. Neither contacts production. No safe automatic fixer is configured.
- `make setup` prepares local dependencies and creates missing inventory without overwriting it. `make bootstrap` is LIVE/MUTATING with native password prompting and dedicated local key generation; `make verify` is LIVE verification as `ansible` with key-only login and `sudo -n`. Never run either during offline validation. See `README.md` for prerequisites and the access handoff; a bootstrap recap alone is insufficient.

- Use `develop` as the base for task branches and open Pull Requests into `develop`. Do not merge without an explicit request.
- Keep Ansible changes idempotent and reviewable. Use built-in modules where practical, parameterize host-specific values, and limit privilege escalation to tasks that need it.
- Do not contact a live host, including Ansible `--check`, without explicit approval for that operation. CI must use offline checks and must not contact production.
- Do not read, commit, or expose real inventories, private keys, passwords, tokens, or other secrets. Preserve the existing `LICENSE`.
- Load only the applicable core skill from `.agents/skills/` and its topic references when needed. Follow `.codex-standards.lock.yaml` and the `standards-sync` skill for future updates.
