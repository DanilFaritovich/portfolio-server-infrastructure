# portfolio-server-infrastructure

[Русский](README.ru.md)

Host provisioning through Ansible for an Ubuntu VPS. This stage creates only the
`ansible` automation account, installs its public key and a sudo policy, verifies
new access, then **STOP**. Docker, Compose, networks, firewall, SSH hardening,
Caddy and application deployment are outside this PR's scope.

## Quick Start

Use a Linux x86_64 or arm64 controller (glibc, such as Ubuntu) with Make, a POSIX
shell, curl, tar/gzip, coreutils (including sha256sum) and OpenSSH clients
(`ssh`, `ssh-keygen`, `ssh-keyscan`, `scp`, `sftp`). **Neither Python 3.12 nor uv needs to be
installed beforehand.** Paramiko is installed automatically in the project-local
`.venv`; sshpass is not required. Setup requires no sudo and installs no system packages.
The VPS must already allow root SSH password login and have `/usr/bin/python3`,
`/bin/bash`, sudo, `/usr/sbin/visudo` and an active `/etc/sudoers.d` include.

```bash
git clone https://github.com/DanilFaritovich/portfolio-server-infrastructure.git
cd portfolio-server-infrastructure
make setup

# Edit inventories/production.yml: ansible_host and ansible_port.
# Have the provider fingerprint and recovery console available.
make bootstrap
# For a new host, confirm its fingerprint first; then Ansible prompts for the root password.
make verify
```

`make setup` verifies minimal system tools, installs checksum-verified pinned
uv **0.12.23** into `.tools/bin/uv`, downloads managed Python **3.12** into
`.tools/python`, creates `.venv` from that managed interpreter, installs the
pinned dependencies (including **Paramiko 5.0.0**)/Ansible collections and actionlint, then copies the example
inventory **only if production.yml does not exist**. Existing inventory is never
read or overwritten by setup. `make deps` uses the same toolchain/dependency
mechanism without creating inventory. Repeated setup reuses the pinned uv, compatible managed Python and
`.venv`; it does not destroy them or reinstall Python unnecessarily. Package
installation reconciles the pinned requirements, and existing collections and
compatible actionlint are reused. Setup needs network access to dependency
sources; it never contacts a VPS.

Edit only the hostname/address and existing SSH port for the standard path; `ansible_user` defaults to `root`. Keep the one-host `bootstrap` structure
and never store passwords or key bytes in inventory.

**First-use trust is handled inside `make bootstrap`.** Keep recovery console
access and a working administrative session available. For an existing entry in
`~/.ssh/known_hosts`, bootstrap uses the stored trust without rescanning or
replacing it. Changed keys still fail strict checking.

For a new host, bootstrap retrieves public host keys with OpenSSH `ssh-keyscan`
and displays the hostname/IP, port, selected key type and SHA256 fingerprint
computed by `ssh-keygen`. It selects one key, preferring Ed25519, then ECDSA,
then RSA. This is **first trust**: the network response does not establish the
server identity. Compare the displayed fingerprint with the VPS provider panel
or console before answering `Trust this host? [y/N]`. Only `y` or `yes` saves the
displayed key to your `~/.ssh/known_hosts`; other input or EOF stops bootstrap
before automation-key generation, password prompting or VPS configuration changes.
No separate `ssh` command is needed just to populate `known_hosts`.

Non-default ports use `[host]:port` entries. Retrieval/fingerprint failures and
absence of an interactive TTY stop first trust. `make verify` never offers first
trust or retrieves keys; run bootstrap first for a new host. Strict host-key
checking remains enabled for both Paramiko bootstrap and OpenSSH verification;
there is no silent trust. See [OpenSSH ssh-keyscan](https://man.openbsd.org/ssh-keyscan)
and [ssh-keygen](https://man.openbsd.org/ssh-keygen).
Confirm VPS prerequisites and the sudoers include before proceeding. Do not select
an unrelated existing account as the managed `ansible` account.

## Access and security

The standard path is **root + interactive SSH password → ansible + dedicated
SSH key + NOPASSWD sudo**. Root is used only for initial bootstrap. Subsequent
provisioning must use `ansible`; `make verify` explicitly overrides the initial
inventory login with `ansible` and never uses a root password.

`make bootstrap` creates an Ed25519 key locally if neither member of the pair
exists, immediately before bootstrap. `make setup` never generates SSH keys:

```text
~/.ssh/portfolio-server-infrastructure/ansible_ed25519
~/.ssh/portfolio-server-infrastructure/ansible_ed25519.pub
```

The directory is protected with `0700`, and the private key with `0600` or
stricter permissions. Existing keys are never overwritten. An incomplete pair,
symlinks, unsafe permissions or a key path inside this repository cause failure.
The wrapper only inspects private-key metadata; the private key remains on the
controller and is used only by its SSH client. The bootstrap role receives only
the public-key path, reads that public key locally and adds it to
`/home/ansible/.ssh/authorized_keys`, preserving unrelated authorized keys.
Keep all SSH keys, real inventories, credentials and logs out of Git.

Generated keys have **no passphrase** for unattended provisioning. Possession of
this private automation key, together with unrestricted `NOPASSWD: ALL`, grants
**root-equivalent access to the VPS**. Protect the controller and key backups.
Running `make bootstrap` deliberately approves that policy; the role's default
consent remains `false`. A dedicated root-owned `/etc/sudoers.d/ansible` file uses
`0440` and is validated with `visudo -cf`. No login password is set for `ansible`.

The initial root connection uses `ansible.builtin.paramiko_ssh` from pinned
Ansible Core **2.18.6**, with project-local Paramiko **5.0.0**. Ansible's native
`--ask-pass` prompts interactively and keeps the password in process memory;
our wrapper never reads or stores it. It is not passed in command arguments,
environment variables or files, and is never saved in inventory, `.env`,
configuration or shell history. Use a normal interactive terminal; do not record
secret input or supply passwords through shell commands.

Initial bootstrap disables SSH agent authentication and private-key lookup and
checks the verified `known_hosts` entry; automatic host-key addition is disabled.
Both the automatic handoff verification and `make verify` use **OpenSSH + the
dedicated private key + public-key-only authentication**, with password prompts
and agent use disabled. Paramiko is limited to initial password-based bootstrap.
See [the pinned Ansible Paramiko transport documentation](https://docs.ansible.com/projects/ansible-core/2.18/collections/ansible/builtin/paramiko_ssh_connection.html).
The plugin is deprecated in newer Ansible releases and scheduled for removal in
2.21; re-evaluate initial password transport before upgrading Ansible to that version.

## Commands and boundaries

| Target | Purpose | Host access |
| --- | --- | --- |
| `make setup` | Install local dependencies; create missing local inventory | Dependency registries only |
| `make deps` | Install pinned local tooling/collections | Dependency registries only |
| `make bootstrap` | Create/reuse dedicated key, bootstrap account, then verify | **LIVE / MUTATING** |
| `make verify` | Verify existing key-only ansible access | **LIVE / verification**, no managed configuration changes |
| `make check` | YAML/Ansible lint, syntax, actionlint, wrapper tests | **OFFLINE** |
| `make ci` | Same offline checks as `make check` | **OFFLINE** |

Bootstrap validates prerequisites, the local inventory, host/port and known-host
trust, with explicit first-use confirmation, before generating a key or requesting
the initial password. It runs the
existing bootstrap role with explicit sudo consent, then opens independent
key-only SSH connections as `ansible`. Verification checks Ansible ping,
`id -un == ansible` and `sudo -n id -u == 0`; every failed stage returns an error.
SSH connection sharing with the initial login is disabled. No further host
provisioning follows verification.

`make verify` uses the same verification playbook without running the bootstrap
role or creating a key. Password authentication and prompts are disabled. Its
purpose is read-only: Ansible may create and remove transient module files, but
it does not change account or host configuration. Keep fallback access if it
fails. A successful bootstrap recap alone is insufficient proof of the handoff.

Checks always use `inventories/production.example.yml`, never production
inventory, keys, passwords or VPS connections. Wrapper tests use temporary
synthetic fixtures and mocked processes, including mocked key generation. Access
tests cover bootstrap without sshpass, Paramiko password transport, OpenSSH
key-only verification, credential-free arguments/environment, bootstrap-only
key generation and the pinned plugin with a mock SSH client, including host-key
mismatch rejection. First-trust tests cover existing/new trust, acceptance, rejection/EOF,
retrieval/fingerprint failures, non-default ports, missing TTY and verification
without first trust, using mock retrieval and offline OpenSSH on synthetic public keys. Setup tests run shell scripts with an isolated PATH without system Python/uv and
fake downloads, checking fresh/repeated setup, inventory preservation, reuse,
arm64, prerequisite failures and checksum/version failures.
GitHub Actions downloads dependencies and runs only `make ci`, with no production
credentials. Offline success does not prove live access or runtime idempotency.
No safe automatic formatter (`make fix`) is configured. For targeted diagnosis:
`make lint-yaml`, `make lint-ansible`, `make syntax-check`, `make lint-workflows`,
`make test-access`. Configure `offline-validation` as a required branch-protection
check separately.

## Overrides and troubleshooting

Make accepts a local inventory path and an absolute private-key path outside the
repository. Use the same overrides for both live targets:

```bash
make bootstrap INVENTORY=/absolute/path/production.yml AUTOMATION_KEY=/absolute/path/dedicated/key
make verify INVENTORY=/absolute/path/production.yml AUTOMATION_KEY=/absolute/path/dedicated/key
```

The sibling `.pub` must exist for an existing key. Use a dedicated unencrypted
key for this wrapper; encrypted existing keys cannot authenticate in its
non-interactive verification. Existing key-directory permissions must already
be `0700` or stricter; repair unsafe local permissions deliberately. A missing
pair is generated, but a partial pair is never repaired or replaced automatically.

An existing administrator can replace `ansible_user: root` in inventory without
changing the role. It must support SSH password login and sudo; bootstrap then
also requests its sudo password through native `--ask-become-pass`. The managed
user for these Make targets remains `ansible`. Inventory supports only one host
and the example's host, port, initial user and Python-interpreter fields;
credentials and extra runtime variables are rejected.

All generated runtimes/tooling stay in ignored `.tools`, `.venv`, `.ansible`
and `.cache` directories. uv release archives and SHA256 values are pinned in
`scripts/install-uv.sh` ([official release](https://github.com/astral-sh/uv/releases/tag/0.12.23)); Python/Ansible dependencies and `ansible.posix` are pinned in
the requirements files. actionlint's version and checksums remain pinned in its
installer. Python's patch version is selected by pinned uv within the 3.12 series;
an existing compatible managed 3.12 runtime is reused. `UV_PYTHON_INSTALL_DIR`
and `UV_CACHE_DIR` are set to project-local paths by setup. No global PATH or
system Python is modified, and neither preinstalled uv nor Go is required.

Checksum/version failures stop setup before inventory creation. An incompatible
local uv/actionlint or an incomplete/incompatible `.venv` is preserved and
reported, rather than silently replaced. Inspect it and move/remove only the
affected local tool/environment before retrying `make setup`. No manual runtime
installation, shell exports or environment activation are needed.

Do not use production `--check` as an offline test: it contacts the host and does not verify a newly created login.
Deliberately repeating bootstrap to assess `changed=0` is another live, mutating
operation, requiring separate authorization. This PR has performed no VPS access.

## License

See [LICENSE](LICENSE). The existing license is preserved.
