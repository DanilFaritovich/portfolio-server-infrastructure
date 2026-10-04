# portfolio-server-infrastructure

[Русский](README.ru.md)

Ansible infrastructure for a personal Ubuntu VPS. The first stage prepares a
managed `ansible` user through an existing administrative SSH account, adds a
controller-provided public key, and installs an explicitly approved passwordless
sudo policy. It stops there. Offline validation has passed; live execution and
independent verification of the new account have not been performed.

## Scope and prerequisites

The developer controller needs Linux x86_64 or arm64, Make, a POSIX shell, curl,
tar (with gzip support), and coreutils (including sha256sum). Python 3.12 must
be available as `python3.12`, with venv and pip support. For the project-local
Python preparation below, you also need uv available on PATH. Go is not required.
Python tools and `ansible.posix` are pinned in `requirements-dev.txt` and
`requirements.yml`; actionlint v1.7.7 and its archive SHA256 checksums are pinned
in `scripts/install-actionlint.sh`. Dependency setup downloads packages and a
prebuilt release from GitHub. Checks are offline after setup.

Before bootstrap, independently confirm the existing host, SSH port, authorized
administrator, host fingerprint and recovery console. The target must already
have `/usr/bin/python3`, `/bin/bash`, sudo, `/usr/sbin/visudo`, and an active sudoers
include for `/etc/sudoers.d`. The current administrator must be able to become
root. This stage does not install those prerequisites or change SSH settings.

The default managed account is `ansible`, with home `/home/ansible` and shell
`/bin/bash`. Username can be overridden; its home must be `/home/<username>`.
Do not select an existing unrelated account or the current bootstrap login.
No account password is provisioned, and existing supplementary groups and
unrelated authorized keys are preserved. Home and SSH file ownership/modes are
managed explicitly. The new account is intended for public-key authentication.

`bootstrap_user_allow_passwordless_sudo` defaults to `false`. Bootstrap fails
before account changes unless the operator explicitly sets it to boolean `true`.
This selects unrestricted `NOPASSWD: ALL`, which is root-equivalent. A dedicated
root-owned `0440` sudoers fragment is validated with `visudo -cf` before activation.
Review this policy before opting in.

Only an absolute path to a readable regular `.pub` file is accepted. Symlinks are
rejected. The file is read on the controller and must contain one OpenSSH RSA,
Ed25519, or NIST ECDSA public key. Key tasks suppress key material from output.
Private keys are never read or copied by the playbook. Keep real inventories,
public/private key material, credentials and logs out of Git.

## Local setup and offline validation

Run from the repository root. Keep the existing local Python 3.12 / `.venv`
approach. If Python 3.12 is not already available, prepare it locally with uv:

```bash
export UV_PYTHON_INSTALL_DIR="$PWD/.tools/python"
export UV_CACHE_DIR="$PWD/.cache/uv"
uv python install 3.12 --no-bin
mkdir -p .tools/runtime-bin
ln -sf "$(uv python find --managed-python 3.12)" .tools/runtime-bin/python3.12
```

For each new terminal using this local runtime, expose it and keep pip's cache
inside the project:

```bash
export PATH="$PWD/.tools/runtime-bin:$PATH"
export PIP_CACHE_DIR="$PWD/.cache/pip"
```

The Python runtime lives under `.tools/python`, with a `python3.12` symlink in
`.tools/runtime-bin`. `make deps` creates `.venv` using `python3.12 -m venv`,
installs the pinned Python/Ansible tools there, and installs collections into
`.ansible/collections`. It downloads the pinned prebuilt actionlint binary for
the controller architecture, verifies its SHA256 checksum, and installs it as
`.tools/bin/actionlint`. No Go runtime or compilation is involved.

`.tools`, `.venv`, `.cache` and `.ansible` are ignored project-local directories;
they are not system installations. Neither setup nor checks install tools
system-wide. Setup needs network access to dependency sources, but does not
contact the VPS:

```bash
make deps
```

Run one aggregate offline check:

```bash
make check
```

`make check` and `make lint-workflows` use `.tools/bin/actionlint` directly;
there is no need to add actionlint to PATH.

`make ci` uses the same aggregate. For isolated diagnosis, use only the relevant
target rather than repeating all checks:

```bash
make lint-yaml
make lint-ansible
make syntax-check
make lint-workflows
```

Syntax checks and Ansible lint use the safe example inventory. They never execute
tasks, load a real public key, or contact a managed host. There is no `make fix`
or `make verify`: no safe automatic formatter or disposable integration test is
configured. Lint/syntax success does not demonstrate runtime idempotency or access.

GitHub Actions installs dependencies and runs `make ci` for PRs into `develop` and
`main`, and pushes to those branches. CI uses no production inventory or secrets.
Configure the `offline-validation` job as a required check in branch protection;
repository settings are a separate manual step.

## Manual first bootstrap

Keep a working administrative SSH session open and recovery console available.
Complete the offline checks first. The following local preparation does not
connect to the VPS:

```bash
cp inventories/production.example.yml inventories/production.yml
```

Edit the ignored `inventories/production.yml`: replace the example host, initial
`ansible_user`, existing SSH port and Python path if necessary. Keep the host alias
`portfolio` for the commands below. Do not switch the inventory to user `ansible`
before that account exists. Do not put passwords or actual key bytes in inventory.

Set these controller-side variables to your actual, independently verified values;
the sample strings are placeholders, not a server configuration:

```bash
export VPS_HOST='your-verified-host'
export VPS_PORT='your-existing-port'
export VPS_ADMIN='your-existing-admin'
export BOOTSTRAP_PUBLIC_KEY='/absolute/path/to/automation_key.pub'
export BOOTSTRAP_PRIVATE_KEY='/absolute/path/to/automation_key'
```

The private-key variable is used only by your SSH client during independent login
verification. The playbook receives only `BOOTSTRAP_PUBLIC_KEY`. Administrative
authentication can use your existing SSH config/agent; add `--private-key` with
the existing administrator key if necessary. Unlock an encrypted key in your
local agent yourself if needed.

**LIVE: the next command connects to the VPS.** Verify the fingerprint through a
trusted channel; do not disable host-key checking. Inspect the current sudo policy
and Python availability, then retain this session as fallback:

```bash
ssh -p "$VPS_PORT" "$VPS_ADMIN@$VPS_HOST"
# In that remote administrative session:
command -v python3
sudo -l
sudo /usr/sbin/visudo -c
```

Confirm the sudoers include for `/etc/sudoers.d` through your administrative
review before proceeding. This implementation checks prerequisite paths, but
does not rewrite the main sudoers file or enable that include.

**LIVE, MUTATING: from a separate controller terminal, bootstrap the account.**
This is deliberate consent for unrestricted passwordless sudo:

```bash
.venv/bin/ansible-playbook -i inventories/production.yml playbooks/bootstrap.yml \
  --limit portfolio --ask-become-pass \
  -e "$(.venv/bin/python -c 'import json, os; print(json.dumps({"bootstrap_user_public_key_path": os.environ["BOOTSTRAP_PUBLIC_KEY"]}))')" \
  -e '{"bootstrap_user_allow_passwordless_sudo": true}'
```

Omit `--ask-become-pass` if the existing administrator is root or already has
passwordless sudo. The local Python snippet serializes only the public-key path
as JSON, including paths containing spaces; it does not read any key file.
Stop on any failure; do not disable validations or expand the task to hardening.

There is no automatic live target in Make or CI. A production `--check` run also
contacts the host and may fail on dependent key/file tasks if the user does not
exist; it cannot verify a subsequent login. Do not treat it as offline validation
or replace the independent handoff with its recap.

## Independent access handoff and STOP

**LIVE: from another controller terminal, verify new key-only access and sudo.**
These commands force public-key authentication with the selected private key:

```bash
ssh -p "$VPS_PORT" -i "$BOOTSTRAP_PRIVATE_KEY" \
  -o IdentitiesOnly=yes -o PreferredAuthentications=publickey \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
  "ansible@$VPS_HOST" 'id -un && sudo -n -l && sudo -n id -u'
```

Expect username `ansible`, the intended sudo policy, and final UID `0`; check
all output and the command's exit status. A successful recap alone is insufficient.
If login or sudo fails, retain the old administrative session and investigate
that failure rather than hardening SSH.

Optional **LIVE** Ansible verification after the SSH/sudo handoff uses the same
host alias with explicit connection overrides. No account-changing role runs:

```bash
.venv/bin/ansible portfolio -i inventories/production.yml \
  -u ansible --private-key "$BOOTSTRAP_PRIVATE_KEY" -e ansible_user=ansible \
  -m ansible.builtin.ping
.venv/bin/ansible portfolio -i inventories/production.yml \
  -u ansible --private-key "$BOOTSTRAP_PRIVATE_KEY" -e ansible_user=ansible \
  --become -m ansible.builtin.command -a 'id -u'
```

To assess idempotency, deliberately repeat the same **LIVE, MUTATING** bootstrap
command through the original administrator; an already-correct host should show
`changed=0`. This is a separate real execution, not an offline check.

STOP after independent access/privilege verification. No Docker, proxy, firewall,
SSH hardening, port change, root-login removal, password-authentication change or
deployment is implemented or authorized by this stage. Keep fallback access.

## License

See [LICENSE](LICENSE). The existing license is preserved.
