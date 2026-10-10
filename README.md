# portfolio-server-infrastructure

[Русский](README.ru.md)

Host provisioning through Ansible for an Ubuntu VPS. The pipeline is:

```text
local setup -> bootstrap managed automation user -> verify access
-> provision Docker host -> verify Docker
-> firewall + validated SSH host ports -> verify hardening
-> human access -> verify users -> final SSH policy -> verify SSH security
-> separately confirmed server operations -> verify operations -> STOP
```

Docker Engine, Compose and Buildx are prepared for future workloads. Caddy,
application networks/Compose files, Vue, domains/TLS, GHCR authentication,
deployment/CD, fail2ban and
automatic upgrades belong to separate stages.

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
make bootstrap-user
# For a new host, confirm its fingerprint first; then Ansible prompts for the root password.
make verify-access
make docker-host
make verify-docker
# Review hardening settings and provider recovery/network access below.
make inspect-hardening
make harden
make verify-hardening
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

Collection versions are pinned in `collections.yml` and installed explicitly by
setup/deps. This filename avoids ansible-lint's automatic requirements discovery;
`make check` keeps `--offline` and still reports missing collections. Make places
the project `.venv/bin` first in PATH so Ansible subprocesses use the same toolchain.

Edit the hostname/address and existing SSH port. `bootstrap_login_user` defaults to `root`;
`ansible_user` selects the non-root automation account (example: `ansible`), and
`ansible_private_key_file` selects its local private-key path. Keep the one-host `bootstrap` structure
and never store passwords or key bytes in inventory.

**First-use trust is handled inside `make bootstrap-user`.** Keep recovery console
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
absence of an interactive TTY stop first trust. `make verify-access` never offers first
trust or retrieves keys; run bootstrap first for a new host. Strict host-key
checking remains enabled for both Paramiko bootstrap and OpenSSH verification;
there is no silent trust. See [OpenSSH ssh-keyscan](https://man.openbsd.org/ssh-keyscan)
and [ssh-keygen](https://man.openbsd.org/ssh-keygen).
Confirm VPS prerequisites and the sudoers include before proceeding. Do not select
an unrelated existing account as the managed `ansible_user` account.

## Access and security

The standard path is **bootstrap_login_user + interactive SSH password →
ansible_user + dedicated SSH key + NOPASSWD sudo**. The initial login is used only
for bootstrap. Stage 1–5 operations and verification use the managed user and key
from inventory, with independent key-only SSH and non-interactive sudo.

`make bootstrap-user` creates an Ed25519 key locally if neither member of the pair
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
`/home/<ansible_user>/.ssh/authorized_keys`, preserving unrelated authorized keys.
Keep all SSH keys, real inventories, credentials and logs out of Git.

Public-key validation and reading run in an explicit controller-local block,
using the playbook's Python interpreter without sudo. Host/port come from the
local inventory. Runtime connection overrides are scoped only to the VPS alias
in a temporary inventory overlay (0600, removed after Ansible exits), rather
than global connection extra-vars; delegated localhost keeps its local context.
Only role inputs remain in `-e`. The overlay contains no passwords or key contents.

Keys generated automatically by `bootstrap-user` have **no passphrase** for unattended provisioning. Existing encrypted keys can be reused after loading them into the local SSH agent. Possession of
this private automation key, together with unrestricted `NOPASSWD: ALL`, grants
**root-equivalent access to the VPS**. Protect the controller and key backups.
Running `make bootstrap-user` deliberately approves that policy; the role's default
consent remains `false`. A dedicated root-owned `/etc/sudoers.d/<ansible_user>` file uses
`0440` and is validated with `visudo -cf`. No login password is set for `ansible_user`.

The initial root connection uses the local `portfolio_password` adapter around
`ansible.builtin.paramiko_ssh` from pinned
Ansible Core **2.18.6**, with project-local Paramiko **5.0.0**. Ansible's native
`--ask-pass` prompts interactively and keeps the password in process memory;
our wrapper never reads or stores it. It is not passed in command arguments,
environment variables or files, and is never saved in inventory, `.env`,
configuration or shell history. Use a normal interactive terminal; do not record
secret input or supply passwords through shell commands.

The adapter reuses the builtin SSH implementation and sets `look_for_keys=False`,
`host_key_auto_add=False` and `record_host_keys=False` through the plugin's
`set_options(direct=...)` API. Core 2.18.6 exposes no variable bindings for the
first two options; their environment/INI bindings also configure deprecated
globals. Those environment settings are removed from child processes, and
deprecation warnings remain enabled.

Initial bootstrap disables SSH agent authentication and private-key lookup and
checks the verified `known_hosts` entry; automatic host-key addition is disabled.
Both the automatic handoff verification and `make verify-access` use **OpenSSH + the
dedicated private key + public-key-only authentication**, with password prompts
disabled and support for the selected key through `ssh-agent`. Paramiko is used for
initial password-based bootstrap and cryptographic SSH host-key verification
when transferring trust between ports.
See [the pinned Ansible Paramiko transport documentation](https://docs.ansible.com/projects/ansible-core/2.18/collections/ansible/builtin/paramiko_ssh_connection.html).
The plugin is deprecated in newer Ansible releases and scheduled for removal in
2.21; re-evaluate initial password transport before upgrading Ansible to that version.

## Commands and boundaries

| Target | Purpose | Host access |
| --- | --- | --- |
| `make setup` | Install local dependencies; create missing local inventory | Dependency registries only |
| `make deps` | Install pinned local tooling/collections | Dependency registries only |
| `make generate-user-key` | Generate a local human Ed25519 keypair and offer agent loading | **LOCAL / key files and optional local agent** |
| `make load-user-key` | Load the selected existing key into the local SSH agent | **LOCAL / agent only** |
| `make show-public-key` | Display public key and SHA256 fingerprint | **LOCAL / read-only** |
| `make copy-public-key` | Copy the complete public key; offer missing clipboard package installation | **LOCAL / clipboard, optional APT install** |
| `make copy-server-trust` | Copy verified server trust JSON; offer missing clipboard package installation | **LOCAL / clipboard, optional APT install** |
| `make show-server-trust` | Export existing OpenSSH server host trust and SHA256 fingerprints | **LOCAL / read-only** |
| `make trust-server` | Import verified host keys; optionally prove trust on a different inventory port | **LOCAL / known_hosts; optional LIVE host-only handshake** |
| `make show-controller` | Display inventory access and SSH command | **LOCAL / read-only** |
| `make connect-controller` | Interactive managed SSH; offer verified trust for a new port | **LIVE / interactive session** |
| `make connect-user` | Interactive SSH as the selected human user | **LIVE / interactive session** |
| `make bootstrap-user` | Create/reuse dedicated key, bootstrap account, then verify | **LIVE / MUTATING** |
| `make verify-access` | Verify inventory managed key-only access | **LIVE / verification**, no managed configuration changes |
| `make docker-host` | Provision Docker packages, logging policy and services | **LIVE / MUTATING**, managed key-only access |
| `make verify-docker` | Check Docker/services and run a disposable container | **LIVE / verification**, transient container/image-cache changes |
| `make inspect-hardening` | Report all Stage 3 safety findings before harden | **LIVE / read-only**, exit 0 for PASS/WARN, non-zero for FAIL |
| `make harden` | Configure UFW and validated SSH listening ports | **LIVE / MUTATING**, managed key-only access |
| `make verify-hardening` | Verify server SSH listeners, selected SSH access ports, UFW and active Docker/containerd | **LIVE / verification**, no managed state changes |
| `make reboot-host` | Verify access, confirm reboot, wait for recovery, then verify access/Docker/hardening | **LIVE / MUTATING**, interactive confirmation; image cache may change |
| `make inspect-operations` | Inspect Stage 5 readiness | **LIVE / read-only** |
| `make setup-operations` | Configure security updates and bounded journals | **LIVE / MUTATING**, explicit TTY confirmation |
| `make verify-operations` | Verify Stage 5 state | **LIVE / read-only** |
| `make check` | YAML/Ansible lint, syntax, actionlint, wrapper tests | **OFFLINE** |
| `make ci` | Same offline checks as `make check` | **OFFLINE** |

Bootstrap validates prerequisites, the local inventory, host/port and known-host
trust, with explicit first-use confirmation, before generating a key or requesting
the initial password. It runs the
existing bootstrap role with explicit sudo consent, then opens independent
key-only SSH connections as `ansible_user`. Verification checks Ansible ping,
`id -un == ansible_user` and `sudo -n id -u == 0`; every failed stage returns an error.
SSH connection sharing with the initial login is disabled. Docker provisioning is a separate explicit target; access verification does not run it.

`make verify-access` uses the same verification playbook without running the bootstrap
role or creating a key. Password authentication and prompts are disabled. Its
purpose is read-only: Ansible may create and remove transient module files, but
it does not change account or host configuration. Keep fallback access if it
fails. A successful bootstrap recap alone is insufficient proof of the handoff.

Docker regression tests cover managed key-only orchestration, connection-overlay
isolation, preflight failure before provisioning, example inventory rejection,
Make/CI offline boundaries, unchanged probes and guaranteed smoke cleanup.
Selected safety assertions and daemon-policy convergence run with real Ansible
on temporary local fixtures with network connections blocked. Syntax checks
cover all seven entry-point playbooks; lint includes all three roles.

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
The controller-key regression test runs the real role's local preflight with
synthetic remote host/Paramiko settings and network connections blocked; it checks
local `.pub` validation and rejects missing files and symlinks.
No safe automatic formatter (`make fix`) is configured. For targeted diagnosis:
`make lint-yaml`, `make lint-ansible`, `make syntax-check`, `make lint-workflows`,
`make test-access`. Configure `offline-validation` as a required branch-protection
check separately.

## Docker host stage

`make docker-host` reuses the existing access wrapper, dedicated key and strict
`known_hosts` trust. It does not generate keys or accept new host trust. Before
any Docker mutation it runs `playbooks/verify.yml`: login must be `ansible_user` and
`sudo -n` must reach UID 0. Missing keys fail with a `make bootstrap-user` hint;
failed login/sudo verification stops the stage. Docker tasks use per-task
privilege escalation with non-interactive sudo. `ansible_user` is never added to the
`docker` group. The bootstrap administrator is used only for bootstrap; managed access is used for
the managed host, preserving controller-local execution.

`playbooks/docker-host.yml` calls `roles/docker_host`. The remote inventory Python
must have Ubuntu's `python3-apt` available for non-mutating package inspection;
if it is missing, preflight fails before changes. Prepare it through existing
administrative access before this stage. Supported hosts are
Ubuntu Jammy 22.04, Noble 24.04 and Resolute 26.04 with systemd; architecture
mapping covers amd64, arm64, armhf, ppc64el and s390x. See the role defaults and
[Docker's Ubuntu installation guide](https://docs.docker.com/engine/install/ubuntu/).
The role configures the official stable APT repository with a dedicated ASCII
signing keyring, a pinned SHA256 key checksum, and the host's release/architecture.
A vendor signing-key rotation requires deliberate checksum review. It installs
`docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-buildx-plugin` and
`docker-compose-plugin` with `state: present`; reruns do not upgrade installed
packages. APT metadata refresh runs only when prerequisites/packages are missing
or the managed repository/key changes, keeping a converged rerun at `changed=0`.

All safety inspection precedes package, repository or configuration changes.
Conflicting `docker.io`, `docker-compose`, `docker-compose-v2`, `docker-doc`,
`docker-buildx`, `podman-docker`, `containerd` or `runc` packages stop provisioning.
There is no automatic uninstall, purge or runtime-data deletion. Existing Docker
APT sources must exactly match the managed source; competing sources, custom
Docker/containerd systemd units/drop-ins, unexpected keyring content and orphan
runtime data require manual review. Existing `daemon.json` must contain exactly
the managed policy; invalid or different settings stop the role with a migration
hint. Review existing workloads/configuration and migrate deliberately before
retrying. This stage does not automatically adopt arbitrary runtime installations.

The role enables/starts `docker.service` and `containerd.service`. Its minimal
`/etc/docker/daemon.json` uses the Docker-supported `local` logging driver with
`max-size: 20m` and `max-file: "5"` (five rotated files per container).
Configuration is validated with `dockerd --validate` before replacement; only a
changed config notifies the Docker restart handler. This limits logs for **new
containers**; existing containers retain their creation-time logging policy.
See [Docker local logging](https://docs.docker.com/engine/logging/drivers/local/).
No application networks or deployment configuration are created.

`make verify-docker` first repeats key-only access/sudo verification, then runs
`docker version`, `docker info`, `docker compose version`, `docker buildx version`,
checks active/enabled status for both services and requires the active logging
driver to be `local`. These probes report `changed=0`. The smoke test creates a
`hello-world:latest` container with `--network none`, starts/attaches with a
120-second timeout, then removes its exact ID in an `always` cleanup block,
including on a failed start. Runtime operations accurately report changes.
The smoke test can download an image from Docker Hub and leave it in the Docker
image cache; verification is **not strictly read-only**. No test container is
left running after the cleanup. No cache pruning removes unrelated operator data.

Manual validation after managed access has already been bootstrapped:

```bash
make setup
make check
make verify-access
make docker-host
make verify-docker
make docker-host
make verify-docker
```

The second `make docker-host` should report `changed=0` if external state has not
changed. Live access, installation, runtime behavior and full host idempotency
must be verified manually; the agent has not run these commands against the VPS.

## Host hardening stage (Stage 3)

Stage 3 starts from a verified Docker-ready host. It creates no human/admin users
or personal keys and leaves `PermitRootLogin`, `PasswordAuthentication` and
`KbdInteractiveAuthentication` unchanged. Final access policy belongs to Stage 4.
Before invoking `make harden`, keep a working human/recovery SSH session and verify
provider-console access. Provider security groups must allow every intended SSH
port; Ansible cannot configure the provider's network controls.

Declare port lists under the existing host in the local inventory. Existing
inventories are preserved by setup, so add these fields yourself if needed:

```yaml
ansible_port: 22
ssh_listen_ports: [22, 2222]
# Optional: external access probes (default: all ssh_listen_ports).
ssh_verify_ports: [22, 2222]
firewall_allowed_tcp_ports: [80, 443]
```

`ssh_verify_ports` must be a non-empty list of unique integer ports from
`ssh_listen_ports`, and must include the current `ansible_port`. If your
controller's network blocks port 22, keep
`ssh_listen_ports: [22, 2222]`, use the reachable `ansible_port: 2222`, and set
`ssh_verify_ports: [2222]`. Both server listeners and IPv4/IPv6 UFW rules remain
mandatory; only external SSH/sudo probes use the selected ports. Port 22's external
reachability is not established by this selection. Omission preserves checks on
all listening ports.

The role has no fixed SSH port: omitted `ssh_listen_ports` defaults to the current
`ansible_port`. Web ports default to 80 and 443; Caddy is not installed. Both lists
accept multiple unique integers from 1 to 65535; the additional TCP list may be
empty. The first transition must include the currently verified `ansible_port`.
Thus moving from 22 to 2222 starts with `[22, 2222]`, preserving the working route.
A host already reached on 2222 can use `[2222]` directly. Do not remove the last
human/recovery route before Stage 4. A later inventory-port change also requires
independently verified `known_hosts` trust for that port; this stage never saves
new trust or edits the inventory. Existing UFW rules excluded from the desired
lists cause a safety stop and require deliberate manual migration.

`playbooks/harden.yml` calls `roles/host_hardening`. Safety inspection precedes
mutation: ambiguous activation modes, custom SSH/UFW service/socket units or
nonstandard drop-ins, unsupported legacy `Port`/unmanaged `ListenAddress` directives or nonstandard
SSH Include hierarchies, occupied SSH ports, inactive Docker/containerd and
ambiguous UFW state stop the role. Supported SSH input is the regular
`/etc/ssh/sshd_config` with the standard `/etc/ssh/sshd_config.d/*.conf` include
and role-owned listening directives. Both Ubuntu's active/enabled `ssh.socket`
and conventional `ssh.service` listener mode are supported without switching
activation modes. For Ubuntu 24.04, socket support targets the stock systemd
SSH generator layout; conventional service mode must also pass the same preflight.
This is support for these inspected configurations, not a claim that every Ubuntu
image, older socket migration override, or custom systemd layout works. Coverage is
offline with synthetic fixtures and local Ansible; no Ubuntu 24.04 VM/VPS acceptance
run is claimed. The standard socket dependency drop-in is accepted only with
its exact `After=ssh.socket` and `Requires=ssh.socket` directives; socket address
drop-ins must come from Ubuntu's runtime generator. Custom overrides are rejected.
All existing live SSH listening ports must remain in `ssh_listen_ports`.

A verified set of plain global legacy `Port <integer>` directives may be adopted
from the main file and regular files in the standard include directory. Different
desired ports and repeated declarations of the same port are supported. Every value
must be desired, the current inventory port must be desired and live, and effective
and live SSH ports must contain no ports outside the desired set. `ListenAddress`,
Match-scoped or unsupported Port syntax, a legacy Port alongside the managed block,
nonstandard/nested/conditional or repeated Includes, symlinked configuration files
and custom systemd/socket ownership still stop before mutation.
Diagnostics identify the directive type without dumping SSH configuration.

Read-only preflight records the exact source path, line number, port and file
fingerprints. After all desired SSH UFW rules exist, `portfolio_ssh_adopt` stages
the complete main/include candidate with a managed block, removes only the
approved exact records and retains their inline comments and all unrelated bytes/settings.
Duplicate source/line records are rejected. The managed block contains unique sorted desired ports.
It validates with `sshd -t` and checks effective ports/public-key authentication
with `sshd -T` before writing; an invalid candidate leaves original SSH files intact.
Effective candidate ports must exactly equal the desired set, with public-key authentication enabled.
Source fingerprints are rechecked immediately before writes; source changes since preflight
abort adoption. Snippet and main replacements are
atomic per file, with rollback on a reported write failure; they are not one
filesystem transaction, so interrupted writes require recovery inspection.
Before replacement, adoption persists `/etc/ssh/portfolio-adoption.pending` with
mode 0600. An uncatchable termination, failed rollback, or failed marker cleanup
leaves this signal; both preflight and direct adoption reject a retry. Live listeners
may still use the old configuration while main/includes on disk are partly replaced.
Through recovery access, restore or complete the approved tree, retain the current
route and human authentication policy, validate `sshd -t` and effective desired ports,
and only then clear the marker. Do not reload SSH or delete the marker blindly.
Existing service/socket handlers validate and activate the installed configuration,
and the wrapper then verifies independent connections on every selected `ssh_verify_ports` entry.
After convergence there is no legacy directive and the next run reports `changed=0`.

Preflight validates stock generator/drop-in structure without requiring the generated
file on disk to match currently loaded listeners or `sshd -T`: these states can
belong to different reload cycles. After `daemon-reload`, generated `ListenStream`
entries must exactly match desired TCP routes and effective `sshd -T` ports.
Loaded systemd `Listen` and live listeners may still retain the old safe subset
until restart. After restart all three route sets must exactly match desired
routes (address family, wildcard bind and port). Inspection combines every
`Listen=` row emitted by `systemctl show`, including Ubuntu's explicit
`0.0.0.0:<port>` / `[::]:<port>` pair. IPv6 wildcard coverage of IPv4 follows
`BindIPv6Only` and, for `default`, `/proc/sys/net/ipv6/bindv6only`; a family mismatch
is still rejected. See [systemd socket binding semantics](https://www.freedesktop.org/software/systemd/man/systemd.socket.html#BindIPv6Only=).
Preflight accepts a host listening only on the current inventory SSH port when
the desired list includes future ports. The current port must remain live and
present in the desired list.

Absent UFW is installed with `state: present`. Before first adoption, existing UFW
must be inactive, without unknown or unmanaged raw user rules, with regular
non-symlink base files, parseable IPv4/IPv6/default-policy and boot configuration,
and stock systemd ownership. Safe provider/image changes to base files are preserved;
package hash differences produce one provenance WARN and do not block adoption.
The role records the existing normalized fingerprints in `/etc/ufw/portfolio-hardening.json`;
subsequent runs reject unrelated base/raw-rule changes and unknown rules. No
reset, rule deletion or arbitrary unmanaged configuration replacement is performed.
Managed `ENABLED`, input/output policies and role-updated rule fingerprints continue
to converge without treating the role's own changes as external drift. Effective
`sshd -T` ports are compared as a set, including duplicate identical entries;
the desired inventory port lists must still be unique.
Before UFW mutation, the role records exact raw fingerprints, authorized ports,
normalized recovery fingerprints, and the rules already present in each address
family. After a process interruption, `harden` can resume only exact authorized TCP
allow additions with the role comment, plus its input/output/boot policy changes.
The stock UFW 0.36 empty-template rewrite is recognized for `LOGLEVEL=low/off` and
standard forward policy, including IPv6 rate-limit capability variants. Other bytes,
unknown tuples/raw rules, duplicate rules, rule removal, and protected base drift
remain blockers. Missing raw files or unsupported initial template/logging layouts
fail closed; no inferred rewrite or reset is performed. An old ownership marker can
upgrade only while its original fingerprints match; it cannot authorize an already
stale ruleset. Standalone verification rejects stale raw fingerprints until `harden`
records the completed state. After any failure, inspect the read-only report and
recovery access before a deliberate retry; do not delete ownership markers.
SSH/UFW configuration, systemd units/drop-ins, and their parent directories must be
root-owned with root group and no group/other write permission. Symlink/type guards
remain in force; Ubuntu's package `/lib` to `/usr/lib` alias is accepted narrowly.
The UFW ownership marker must additionally have no group/other access (0600 or
stricter). Unsafe ownership or modes stop inspection before configuration mutation.
The focused read-only `library/portfolio_hardening_info.py` module performs these
checks. UFW CLI commands are used without an additional collection; their rule
operations are idempotent and report actual additions/updates.

All SSH allow rules precede default incoming deny, default outgoing allow and
UFW enable. Both IPv4 and IPv6 must be enabled and verified. The role prepends a
managed SSH port/public-key block while preserving the rest of the file. The full
candidate is validated with `sshd -t -f` before atomic replacement. A changed
block or unconverged socket state notifies the handler, which repeats `sshd -t`.
Service mode uses a narrow
`ssh.service` reload. Socket mode runs `daemon-reload`, validates the generated
candidate routes and `sshd -T` against the desired list while existing loaded/live
listeners remain available as a safe subset. Candidate validation requires the
generated file to exist and retain the supported stock structure. Candidate
inspection also requires runtime IPv4/IPv6 UFW allow rules for all desired SSH
ports before restarting `ssh.socket` and `ssh.service` in one
ordered transaction. The role then strictly verifies generated, loaded and live
routes, effective SSH ports, Docker/containerd and the active UFW with exact desired
IPv4/IPv6 TCP rules. The wrapper verifies fresh key-only SSH and `sudo -n` on every
`ssh_verify_ports` entry. Runtime mismatch is a hard failure. Preflight checks the actual socket/service dependencies and
`KillMode=process` to preserve established sessions. A generated-port mismatch
stops before listener restart; use recovery access to reconcile configuration
before retrying. Socket drift also schedules these handlers when the installed
SSH block is unchanged, allowing an interrupted transition to converge in one
`make harden` run. Safe pre-transition generated/loaded/live drift is reported as
WARN by `make inspect-hardening`, which remains READY; it becomes PASS after
convergence. A converged
repeat run does not reload or restart SSH.
See [Ubuntu socket activation](https://discourse.ubuntu.com/t/sshd-now-uses-socket-based-activation-ubuntu-22-10-and-later/30189).
See [UFW remote management](https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html)
and [OpenSSH configuration](https://man.openbsd.org/sshd_config).

Both public targets first verify existing independent `ansible_user` key-only access
and `sudo -n`. After provisioning, the wrapper opens fresh connections on **each**
`ssh_verify_ports` entry and repeats access/sudo and hardening checks. It pins the
already trusted identity using [OpenSSH HostKeyAlias](https://man.openbsd.org/ssh_config#HostKeyAlias),
with strict checking and connection sharing disabled. A failed connection stops
immediately; use recovery access, without blindly retrying changes.
`make verify-hardening` uses the same independent connections and read-only
inspection: valid/effective SSH configuration and exact daemon listeners, UFW
active/enabled, deny incoming/allow outgoing, every configured TCP allow rule for
IPv4/IPv6, unchanged ownership fingerprints, and active Docker/containerd.
It installs nothing, invokes no handlers and creates no smoke container.
This is post-convergence verification: every `ssh_listen_ports` route is required
on the server; independent external access is required on every `ssh_verify_ports` entry.
Before the first successful `make harden`, a future port can time out; that failure
alone does not establish lockout of the current inventory route. The wrapper
reports the failed configured port and directs you to `make verify-access` and
recovery access. Stop on failure; proceed to the next manual command only after
the previous command succeeds.
Transient Ansible module files are cleaned up as in access verification.

Docker's own forwarding rules remain unchanged. UFW host-input policy does not
by itself constrain future Docker-published container ports; application network
security remains part of the separate deployment stage. Stage 3 does not change
Docker's iptables management, create application networks, or publish containers.
Provider-side rules and an explicit policy for Docker-published ports need separate
review before application deployment; opening host-input ports here is insufficient.
See
[Docker and UFW](https://docs.docker.com/engine/network/packet-filtering-firewalls/#docker-and-ufw).

Offline regression tests use synthetic inventories and opaque keys, mocked
inspection commands, and real local Ansible with network blocked. They exercise
preflight failures, managed/controller connection isolation, every-port
verification, SSH validation before replacement, unchanged fallback policy,
SSH/UFW convergence, firewall enable ordering and verification without state
writes. These tests do not establish production runtime success.

`make inspect-hardening` is the read-only Stage 3 preflight. It verifies managed
key-only access and `sudo -n` on the current inventory route, then collects all
independent SSH, systemd, Docker/containerd and UFW safety findings in one compact
report. This includes desired/effective/live ports, supported SSH files and legacy
Port adoption, activation mode, disk/generated/loaded socket state, unit overrides,
UFW package baselines, ownership, raw rules and unsafe file types. Config contents,
credentials, command stderr and ownership fingerprints are never printed.

`PASS` means the check already fits. `WARN` means harden can safely adopt or converge
the state, such as supported legacy Ports, absent/inactive pristine UFW or stale
stock socket state. `FAIL` blocks harden. Exit status is 0 without FAIL findings,
including WARN-only reports, and non-zero when inspection is blocked. Resolve all
FAIL findings before running harden; repeated harden attempts are not a diagnosis
workflow. Checks that depend on unavailable/unsafe data are marked as unavailable;
other safe checks continue. Without managed access/sudo, remote inspection cannot
continue. Future SSH ports are inspected without requiring them to be reachable yet.

Inspection streams the same `portfolio_hardening_info.py` implementation used by
harden and verify-hardening over SSH stdin with `sudo -n` and Python `-B`; it creates
no remote payload/temp files. It installs no packages, writes no files, changes no
firewall/systemd state, performs no daemon-reload or SSH reload/restart, and runs no
handlers. It preserves existing strict host trust. A ready report is a snapshot;
harden repeats safety checks before mutation, while verification requires runtime
convergence.

Manual live validation on the already Docker-ready host:

```bash
make verify-access &&
make inspect-hardening &&
make harden &&
make verify-hardening &&
make harden &&
make verify-hardening
```

The second `make harden` must report `changed=0` if external state has not changed.
The agent runs offline checks only; live safety, listeners and idempotency require
this manual validation. STOP after Stage 3 before explicitly invoking Stage 4.

## Confirmed host reboot

After successful Stage 3 verification, invoke `make reboot-host` as a separate
maintenance operation. It is not an automatic provisioning step. First verify
provider-console/recovery access and provider-side SSH rules: reboot will end
existing SSH sessions. Use the same overrides as the other verification commands:

```bash
make reboot-host INVENTORY=/path/to/local-inventory.yml AUTOMATION_KEY=/path/to/automation-key
```

The wrapper first verifies key-only SSH as `ansible_user` and `sudo -n` on the current
inventory port. It then asks `Reboot this host now? [y/N]` in an interactive terminal.
Only `y`/`yes` authorizes reboot; empty input, refusal, EOF, or Ctrl-C stops the command.
Without a TTY it rejects the request before host contact; there is no unattended or
force mode. Existing inventory, automation key, and host trust are reused; no key is
created and password authentication/sudo prompts remain disabled.

`playbooks/reboot-host.yml` uses `ansible.builtin.reboot` with `reboot_timeout: 300`,
`connect_timeout: 10`, and `post_reboot_delay: 5`. Ansible separately bounds waiting
for a new boot ID and the readiness test: allow approximately 600 seconds plus the
delay and SSH/Ansible overhead. After recovery it runs `verify-access`, `verify-docker`,
and `verify-hardening` checks in order with the same inventory/key, including fresh
access on every `ssh_verify_ports` and all server listeners. The Docker smoke test
may change the image cache; no firewall/SSH provisioning runs. Failure returns a
non-zero status identifying the failed phase and stops later checks. The host may
already have rebooted: use recovery console access and do not repeat reboot blindly.
Human-access policy is the separately invoked Stage 4 below; application deployment remains separate.

Offline tests mock all remote/reboot calls; `make check`/CI perform only playbook
syntax checks and local validation. The agent has not performed a real reboot.

## Managed user configuration and migration

The three access fields are configured together on the host in the existing
one-host inventory structure:

```yaml
bootstrap_login_user: root
ansible_user: automation
ansible_private_key_file: ~/.ssh/portfolio-server-infrastructure/automation_ed25519
```

Use absolute or `~/` key paths outside the repository. Bootstrap creates the selected
account and adds its public key without removing existing keys, validates its
`NOPASSWD: ALL` sudo fragment with `visudo`, then independently verifies the selected
key-only login, ping and `sudo -n`. A failed verification is an error; it does not
change inventory, remove accounts or change SSH authentication policy.

Existing inventories with neither new field keep their original meaning:
`ansible_user` is the initial login (normally root), while all later stages use the
old `ansible` account and established key path (or legacy `AUTOMATION_KEY`). Setup
preserves existing inventory without rewriting it. To make the same access explicit,
set `bootstrap_login_user` to the old initial login, `ansible_user: ansible`, and
`ansible_private_key_file` to the existing automation key; verify access before use.

If the original password bootstrap login still works, a candidate inventory may
select the new account/key and run `make bootstrap-user INVENTORY=inventories/migration.yml`.
Its independent verification must succeed before you replace the old inventory.
The old account and SSH policy are retained.

For a VPS already secured through Stage 4/5, retain the old inventory, a working
administrator session and provider-console recovery. Do not reopen root/password
SSH or rerun password bootstrap. With the old managed inventory, create a separate,
previously unused account through the existing `add-user` path, for example:

```bash
make add-user HUMAN_USER=automation HUMAN_SUDO=admin HUMAN_KEY="$HOME/.ssh/portfolio-infra/automation_ed25519"
make verify-user HUMAN_USER=automation HUMAN_SUDO=admin HUMAN_KEY="$HOME/.ssh/portfolio-infra/automation_ed25519"
```

This requires completed Stage 3 and verifies the new admin login/sudo; public-only
imports alone are insufficient: the owner must independently prove access. Keep the device key outside the
repository; encrypted keys can use the existing local agent. Keep separate human recovery access. Create a separate ignored local
candidate inventory with `ansible_user: automation`, the exact new key path and the
existing SSH ports. Explicitly verify it before replacing the working inventory:

```bash
make verify-access INVENTORY=inventories/migration.yml
make verify-docker INVENTORY=inventories/migration.yml
make verify-hardening INVENTORY=inventories/migration.yml
make verify-ssh-security INVENTORY=inventories/migration.yml HUMAN_USER=operator HUMAN_SUDO=admin HUMAN_KEY="$HOME/.ssh/portfolio-infra/operator_ed25519"
make verify-operations INVENTORY=inventories/migration.yml
```

Supply the existing separately verified human admin for SSH security verification.
These are operator LIVE checks; Docker verification can populate its image cache.
If any check fails, keep using the old inventory and recovery access. Only after
successful verification deliberately replace the working inventory. No command
switches it automatically, deletes the old `ansible` account, or alters SSH policy
as part of this migration. Repeated provisioning/idempotency remains a separately
authorized operator check.

## Local keys and interactive SSH

After `make setup` (or `make deps`), local key commands need OpenSSH client tools,
but no inventory, Ansible playbook, VPS account or server connection:

```bash
make generate-user-key HUMAN_USER=operator
make show-public-key HUMAN_USER=operator
```

The default key is `~/.ssh/portfolio-infra/operator_ed25519` with a `.pub` companion.
`KEY_NAME` selects a different private-key filename in the same directory, for example
`KEY_NAME=operator_laptop_ed25519`; it cannot contain directories or end in `.pub`.
`HUMAN_KEY=/absolute/path/to/key` takes precedence over `KEY_NAME`. Use the same inputs
for generation, public-key display and `connect-user`. Existing pairs are preserved;
partial pairs, symlinks, unsafe ownership/permissions and invalid public keys fail.
New directories are `0700` and private files `0600` or stricter. Existing permissions
are validated without silent repair. The only permitted repository key directory is
ignored `secrets/portfolio-infra/`; prefer keys outside the repository.

A new key requires a terminal: `ssh-keygen` asks for a passphrase directly, without
passing it in arguments or storing it in this project. Pressing Enter deliberately
creates an unencrypted key. Existing pairs can be checked again without a terminal.
`show-public-key` prints only the public algorithm/key (without its comment) and
SHA256 fingerprint; it requires a complete local pair and inspects only private-file
metadata. Give only the public key to the administrator. Generation and display do
not create an account or install its key on the VPS; installation is a separate
`add-user` operation. For a custom filename, pass its exact path via `HUMAN_KEY` to
existing Stage 4 commands, which retain their previous defaults.

Load a passphrase-protected key into your existing local `ssh-agent` before connecting:

```bash
make load-user-key HUMAN_USER=operator
make show-controller
make connect-controller
make connect-user HUMAN_USER=operator
```

Start a local `ssh-agent` first if none is running. `show-controller` is local only:
it displays the managed user, server, current inventory port, resolved key path and
shell-quoted ready SSH command. It validates the local pair and existing host trust;
missing keys or trust block the command. `connect-controller` uses that same command;
`connect-user` uses the same inventory host/port with the selected human key and login.
Both connect commands require a terminal and an already installed matching public key.
They open a normal interactive shell and do not run provisioning or verification
playbooks. What you run inside that shell can change the VPS.

SSH requires a trusted entry in `~/.ssh/known_hosts` for `host` (port 22) or
`[host]:port`. `show-controller` and `connect-user` block missing trust; a changed
host key fails during connection. `connect-controller` can offer verified transfer
from another trusted port, as described below. Use `show-server-trust` and
`trust-server` to establish trust on a second computer.
The trust file/directory must be owned by you, not writable by group/others and not
symlinks. SSH uses strict host checking, the selected identity and key-only authentication;
password/keyboard-interactive fallback, agent forwarding, other forwarding and connection
sharing are disabled. Client SSH config is bypassed to keep identity, host, port and
trust source tied to these inputs. Paths with control characters or OpenSSH expansion
tokens are rejected. An unlocked agent can authenticate the selected encrypted key;
without it, authentication fails instead of prompting for a password. Agent support
also applies to `connect-controller`, `verify-access`, Stage 1–5 Ansible and the streaming
inspectors. All select the explicit key with `IdentitiesOnly=yes`; an encrypted key
requires the same invoking shell to have access to its unlocked agent. Unencrypted
keys continue working without an agent. `INVENTORY` and legacy `AUTOMATION_KEY` follow
the task 1 rules; conflicting managed-key overrides fail.

### Transfer server trust to a second computer

Server host keys identify the VPS; they are separate from your user login keys.
Trust import/export requires no private keys or working login and does not use
`ssh-keyscan`. Export and source import are local; `trust-server` can separately
offer a LIVE host-only handshake when the inventory port differs from the JSON port.

`copy-server-trust` reuses the same validated export and clipboard backend as
`copy-public-key`: Wayland (`wl-copy`), X11 (`xclip`/`xsel`) or macOS (`pbcopy`).
Only the JSON is copied; server, port, fingerprints and success confirmation stay
in the terminal. On Ubuntu/Debian, a missing utility offers APT installation with
`Install now? [Y/n]:` (Enter/Y accepts; N cancels installation and copying).
Headless sessions fail with guidance to use `show-server-trust`; non-interactive
calls never install packages. Copy or installation errors never report success.
A VM needs a configured shared clipboard or another reviewed transfer channel.

1. On the already trusted PC, export the server's existing trust:

   ```bash
   make show-server-trust INVENTORY=inventories/production.yml
   # Or copy only the compatible JSON to the desktop clipboard:
   make copy-server-trust INVENTORY=inventories/production.yml
   ```

   `show-server-trust` reads the project's OpenSSH trust source, `~/.ssh/known_hosts`,
   using OpenSSH lookup, including hashed entries and nonstandard ports. It prints
   host, port, each public host key and SHA256 fingerprint, then one JSON transfer
   line. It does not consult alternative client-config or system trust files.
2. Transfer that JSON line through an authenticated channel to PC 2. Verify its
   source and compare fingerprints with PC 1. Export cannot retrospectively prove
   how PC 1 originally established trust; the source computer must already be trusted.
3. On PC 2, prepare its local ignored inventory with exactly the same server
   hostname/IP and the desired SSH port, then import:

   ```bash
   make trust-server INVENTORY=inventories/laptop2.yml
   ```

   Paste the JSON line at `Host trust data:`. The CLI validates public keys with
   OpenSSH, recalculates fingerprints and requires the same hostname/IP as inventory.
   The JSON port must be an integer from 1 to 65535; it may differ from inventory.
   Review the displayed details; enter `yes` only after independently verifying
   the source. Enter, N, EOF or interruption cancels. Non-interactive import fails
   without reading input or writing trust.
   For JSON `132.243.166.145:2222` and inventory `132.243.166.145:22`, the CLI displays
   both endpoints and asks `Import verified trust for port 2222? [y/N]:`.
   Confirmation saves only the source endpoint `:2222`. It then offers
   `Verify and trust configured port 22 now? [y/N]:`. Accepting runs the same signed
   Paramiko handshake used by `connect-controller`, without login, agent access or
   remote commands. Only a matching, cryptographically proven host key can reach
   the separate `Trust this server on port 22? [y/N]:` confirmation and be added.
   Success reports `SUCCESS` for the configured endpoint. Existing matching trust
   needs no probe or duplicate entry; same-port imports retain their local workflow.
   Declining the optional probe preserves source trust and leaves port 22 untrusted.
   A failed handshake, unreachable port, different key or declined final confirmation
   stops destination setup with a nonzero exit and explains that source trust remains.
   Check the endpoint with your administrator/provider console, then retry
   `trust-server` or `connect-controller`. Conflicting records are never replaced;
   neither inventory nor VPS listeners/firewall change. No manual port switching is needed.
4. Once the selected local login key is available and its public key is registered
   on the VPS, use the existing commands:

   ```bash
   make show-controller INVENTORY=inventories/laptop2.yml  # local preflight
   make connect-controller INVENTORY=inventories/laptop2.yml  # LIVE SSH
   make verify-access INVENTORY=inventories/laptop2.yml  # LIVE SSH/sudo verification
   ```

Import preserves unrelated entries and comments, detects existing-key conflicts and
repeated keys (including hashed entries), and atomically replaces the user trust file
only when additions are needed. New `.ssh` directories use 0700; written `known_hosts`
uses 0600. A private local lock serializes imports; changes detected since review stop
the write. Avoid simultaneous edits by other SSH tools. Unsafe ownership, writable
paths, symlinks/hardlinks, revoked keys and certificate-authority entries block import.
Conflicting trust requires administrator-led identity/rotation diagnosis; this command
does not replace conflicting keys. Strict checking remains enabled for interactive
SSH and existing Ansible workflows. Trust import alone does not grant login or sudo.

Without an already trusted PC, obtain the public SSH host key and its SHA256
fingerprint from your administrator or an authenticated VPS provider console. Ask
for the same transfer format, populated with verified values:

```json
{"version":1,"host":"SERVER_HOST_FROM_INVENTORY","port":2244,"keys":[{"public_key":"ssh-ed25519 VERIFIED_PUBLIC_HOST_KEY","fingerprint":"SHA256:VERIFIED_FINGERPRINT"}]}
```

A fingerprint alone does not provide the public key, and matching a fingerprint
supplied alongside an untrusted network key does not authenticate the server.
Do not rerun password bootstrap on a secured server to bypass missing local trust.

### Switch to another SSH port with existing server trust

After an operator has independently configured the VPS listener/firewall, change
only `ansible_port` in your local inventory and run:

```bash
make connect-controller INVENTORY=inventories/laptop2.yml
```

If the new endpoint lacks trust, the interactive CLI searches the same hostname/IP
on previously trusted ports in the local `known_hosts`, including hashed entries.
It displays the old endpoints and completes a bounded SSH handshake on the new
port using the already pinned Paramiko dependency. Negotiation permits only host-key
algorithms backed by existing trust (including RSA SHA2 variants). Paramiko verifies
the key-exchange signature; the presented public key must also equal the trusted
key. No user authentication, private-key/agent access or remote commands occur
in this probe. A network scan or matching IP alone cannot authorize transfer.

Only after this proof does `Trust this server on port …? [y/N]:` offer to save the
verified identity. Enter/N cancels and stops connection without changing trust.
Y appends only the verified key through the existing locked, snapshot-checked,
atomic writer; it preserves other endpoints, keys and comments. Then the original
OpenSSH session starts with strict checking and forwarding disabled. Multiple
host-key algorithms may be trusted, but only the identity proven by this handshake
is added. Repeated execution uses existing endpoint trust without probing or adding
duplicates. An unavailable port, bad signature, different key, conflicting identities
across ports, unsafe metadata or concurrent trust-file changes stop the operation.

Discovery uses the exact inventory hostname/IP, without DNS aliases, wildcard-only
source discovery or port scans. It enumerates port names locally to recognize hashes;
stores with more than 32 distinct hashed entries or unsupported hash formats fail
safely and require explicit `show-server-trust`/`trust-server` transfer for the desired
endpoint. No VPS configuration, inventory editing or host-key rotation is performed.
`show-controller` remains read-only and never probes or imports. Non-interactive
Ansible paths, including `verify-access`, still fail on missing trust without prompts
or network key retrieval. LIVE access and VM clipboard integration remain manual
operator checks; offline tests do not prove production access.

### Agent loading and a new computer with one encrypted key

After creating a new pair, `generate-user-key` asks `Add private key to ssh-agent? [Y/n]:`.
Enter/Y loads the selected key through native OpenSSH `ssh-add`; N skips loading.
OpenSSH owns passphrase input: Python never reads it. Successful loading prints only
the selected public fingerprint. Generation stays successful if agent loading fails;
the key is preserved. `load-user-key` reports failure with a nonzero exit status.
Existing pairs are preserved and do not trigger another prompt by default. Use
`load-user-key` for them, with the same `HUMAN_USER`, `HUMAN_KEY` or `KEY_NAME` selection.
Neither command needs inventory or runs an Ansible playbook.

The CLI reuses the current agent, including an empty agent; it never launches one.
An already loaded selected fingerprint succeeds without adding other identities.
Missing/unreachable agents produce instructions; a stalled agent query times out
after 10 seconds. Start an agent in the parent shell only when needed:

```bash
eval "$(ssh-agent -s)"
make load-user-key HUMAN_USER=portfolio_laptop2
```

`AGENT_LOAD=ask` (default), `yes` or `no` controls loading during generation. `yes`
omits confirmation; `no` skips agent access. New key generation still requires a TTY
for native passphrase input. Without a TTY there is no confirmation or passphrase
prompt: `load-user-key` can confirm an already loaded identity, but refuses to add
an unloaded key. Even `AGENT_LOAD=yes` cannot bypass that rule. Generation preserves
its success and reports any loading failure; use `load-user-key` when automation
must check loading with a nonzero failure status. Askpass is disabled during loading.

On the new computer, use a reviewed checkout of this feature and OpenSSH client
prerequisites. Keep a separate recovery administrator and the first controller:

```bash
make setup INVENTORY=inventories/laptop2.yml
make generate-user-key HUMAN_USER=portfolio_laptop2
make load-user-key HUMAN_USER=portfolio_laptop2
make copy-public-key HUMAN_USER=portfolio_laptop2
```

Choose a passphrase and accept agent loading. If no agent was available, start it in
the parent shell and run `load-user-key`. Copy only the public key to PC 1 through
a reviewed transfer channel or explicitly configured VM shared clipboard; the CLI
does not synchronize clipboards between computers. Compare its SHA256 fingerprint.
After separate LIVE authorization, PC 1 registers
the new administrator through its existing `ansible` controller:

```bash
make add-user INVENTORY=inventories/production.yml HUMAN_USER=portfolio_laptop2 \
  HUMAN_SUDO=admin
# Paste the public key at >, compare user/rights/fingerprint, then explicitly confirm.
```

`copy-public-key` selects the same key as `show-public-key`, including `HUMAN_KEY`
and `KEY_NAME`, and copies the complete `.pub` contents, including the comment.
It needs only the public file and never inspects the private member, contacts a host,
or loads an agent. In a Wayland session it prefers `wl-copy` (package `wl-clipboard`);
in X11 it uses `xclip` or `xsel` (matching packages). macOS uses built-in `pbcopy`.
On Ubuntu/Debian, a missing utility offers `Install now? [Y/n]:` in a terminal:
Enter/Y installs `wl-clipboard` or `xclip` through APT (with sudo unless root), checks
availability and retries copying. N declines without installing or copying.
`make setup` does not install clipboard packages. Non-interactive calls never prompt
or install; headless Linux calls suggest `make show-public-key`. Other Linux systems
require manual installation. Success reports the SHA256 fingerprint; installation
or clipboard errors fail the command without reporting success.
`show-public-key` remains available for text transfer without clipboard utilities.

Without `HUMAN_PUBLIC_KEY`, `add-user` asks for one plain OpenSSH public-key line
in a terminal. Both pasted keys and files use the same format and OpenSSH validation;
private-key blocks, key options, multiple keys and invalid key data are refused.
Before host contact, the CLI displays the user, `HUMAN_SUDO` and SHA256 fingerprint,
then asks for explicit confirmation with default deny. Temporary public-key snapshots
use a private directory and a `0600` file, removed on completion or failure.
File import remains supported:

```bash
make add-user HUMAN_USER=portfolio_laptop2 HUMAN_SUDO=admin \
  HUMAN_PUBLIC_KEY=/path/portfolio_laptop2_ed25519.pub
```

In a noninteractive run, `HUMAN_PUBLIC_KEY` is required and retains the existing
explicit-file automation behavior without a prompt. In a terminal, file imports
also require confirmation. Registration is additive and reports access as
**UNVERIFIED**; the owner must independently verify SSH and Ansible from PC 2.
`add-user` no longer generates a local key when public input is absent; use
`generate-user-key` before registration.

On PC 2, edit only its ignored candidate inventory: preserve the verified host,
current port, Python interpreter and hardening port lists; set `bootstrap_login_user`
alongside `ansible_user: portfolio_laptop2` and
`ansible_private_key_file: ~/.ssh/portfolio-infra/portfolio_laptop2_ed25519`.
Use `make show-server-trust` on PC 1 and `make trust-server
INVENTORY=inventories/laptop2.yml` on PC 2 as described above; do not rerun bootstrap
or auto-accept trust on a secured server. The same key is used below, after LIVE approval:

```bash
make show-controller INVENTORY=inventories/laptop2.yml  # local only
make connect-controller INVENTORY=inventories/laptop2.yml
# In the fresh shell: id -un -> portfolio_laptop2; sudo -n id -u -> 0; exit
make connect-user INVENTORY=inventories/laptop2.yml HUMAN_USER=portfolio_laptop2
make verify-access INVENTORY=inventories/laptop2.yml
```

`verify-access` checks Ansible connectivity, login and noninteractive sudo. Stage 1–5
OpenSSH and streaming paths inherit `SSH_AUTH_SOCK` and use only their explicit key;
no second unencrypted key is required. An unloaded encrypted identity fails in batch
mode without password fallback. Final SSH security still requires a distinct proven
human administrator; `verify-user` cannot target the current inventory controller.

For an isolated Ubuntu 24.04 VM, first run `make check` offline. Then test local key
creation, Y/Enter/N, `AGENT_LOAD=no`, repeated generation, agent absence and repeated
`load-user-key`. Stop the disposable agent or unset `SSH_AUTH_SOCK` to test refusal;
never stop a shared desktop agent. Fresh SSH and Ansible checks against the disposable
VM require separate approval and a registered key/trusted host. Test that unrelated
loaded identities cannot substitute for the selected key. Offline mocks do not prove
real VM authentication. This scenario retains the first controller and recovery access.

## Overrides and troubleshooting

Make accepts a local inventory path. Set `ansible_private_key_file` there.
`AUTOMATION_KEY` remains supported for legacy inventories; for the explicit format
it must match the inventory key or the command fails before host contact.
Use the same inventory for all live targets (the key override below is optional and must match an explicit inventory):

```bash
make bootstrap-user INVENTORY=/absolute/path/production.yml AUTOMATION_KEY=/absolute/path/dedicated/key
make verify-access INVENTORY=/absolute/path/production.yml AUTOMATION_KEY=/absolute/path/dedicated/key
make docker-host INVENTORY=/absolute/path/production.yml AUTOMATION_KEY=/absolute/path/dedicated/key
make verify-docker INVENTORY=/absolute/path/production.yml AUTOMATION_KEY=/absolute/path/dedicated/key
```

The sibling `.pub` must exist for an existing key. Encrypted existing keys work
through the invoking shell's unlocked agent; load the selected key first with
`make load-user-key HUMAN_USER=… HUMAN_KEY=/absolute/path/to/key`. Existing key-directory permissions must already
be `0700` or stricter; repair unsafe local permissions deliberately. A missing
pair is generated, but a partial pair is never repaired or replaced automatically.

An existing administrator can replace `bootstrap_login_user: root` in inventory without
changing the role. It must support SSH password login and sudo; bootstrap then
also requests its sudo password through native `--ask-become-pass`. The managed
user is selected by `ansible_user`. Inventory supports only one host
and the example's host, port, bootstrap/managed users, local key path, Python-interpreter and hardening port-list fields;
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

## Human access and final SSH policy (Stage 4)

Run this stage separately after successful Stage 3 verification. All four commands
are **LIVE**. `add-user` and `secure-ssh` mutate the host; verification commands
create fresh SSH sessions and run read-only account/policy probes. They never use
root passwords or change host trust. Keep the same local inventory and
`AUTOMATION_KEY`; every command first verifies managed `ansible_user` key-only SSH,
`sudo -n`, and completed Stage 3 on every `ssh_verify_ports` route.

```bash
# Create/load the key locally; paste its public member during registration.
make generate-user-key HUMAN_USER=portfolio_admin
make show-public-key HUMAN_USER=portfolio_admin
make add-user HUMAN_USER=portfolio_admin HUMAN_SUDO=admin
make verify-user HUMAN_USER=portfolio_admin HUMAN_SUDO=admin
# Keep an operator session open; confirm tested provider-console recovery interactively.
make secure-ssh HUMAN_USER=portfolio_admin HUMAN_SUDO=admin
make verify-ssh-security HUMAN_USER=portfolio_admin HUMAN_SUDO=admin
```

The default human key is `~/.ssh/portfolio-infra/<HUMAN_USER>_ed25519`, separate
from the automation key. `HUMAN_KEY` overrides that path. The only permitted
repository location is `./secrets/portfolio-infra/`; for example:

```bash
make add-user HUMAN_USER=reader HUMAN_GROUPS=readers HUMAN_GROUPS_APPROVED=readers HUMAN_SUDO=none \
  HUMAN_KEY="$PWD/secrets/portfolio-infra/reader_ed25519"
# Import one existing public key without generating or copying a private key.
make add-user HUMAN_USER=operator2 HUMAN_SUDO=admin \
  HUMAN_PUBLIC_KEY="$HOME/.ssh/operator2.pub"
# Its owner verifies with a matching local private/public pair.
make verify-user HUMAN_USER=operator2 HUMAN_SUDO=admin \
  HUMAN_KEY="$HOME/.ssh/operator2" HUMAN_PUBLIC_KEY="$HOME/.ssh/operator2.pub"
# Explicit limited sudo grant; paths allow any arguments supported by that executable.
make add-user HUMAN_USER=auditor HUMAN_SUDO=restricted \
  HUMAN_SUDO_COMMANDS=/usr/bin/id
```

`HUMAN_USER` is required; `HUMAN_SUDO` defaults to `none`. `admin` installs
`NOPASSWD: ALL`; `restricted` requires comma-separated absolute executable paths
in `HUMAN_SUDO_COMMANDS`, with no arguments, wildcards or sudoers syntax. A path
such as a shell, interpreter or service manager can still grant full root power.
Restricted executable paths must be canonical, executable and root-owned, with
protected root-owned parents; mutable files and symlinks are refused.
`HUMAN_GROUPS` is a comma-separated additive list; missing groups are created.
Known privileged groups are refused even with `HUMAN_SUDO=admin`: root/controller,
Docker/LXD/Incus/libvirt groups, `disk`, `shadow`, `adm`, `systemd-journal`, `kvm`,
`sudoers`, `wheel`, `storage`, `input`, `video` and `render`. `sudo`/`admin` groups
require the admin policy. Every other group, including an unknown or missing group,
is blocked by default: names and GIDs do not prove safety. Review its actual server-side
file/log/device permissions, ACLs, service sockets and administrative policy before approval.
Set `HUMAN_GROUPS_APPROVED` to the exact comma-separated non-sudo groups to explicitly
accept those rights, independently of `HUMAN_SUDO`. Do not approve unaudited groups.
This separate approval is required in interactive and noninteractive usage; no prompt or
sudo policy supplies it implicitly. Existing scripts with non-sudo `HUMAN_GROUPS` must
now supply this approval. Empty groups and admin-policy `sudo`/`admin` membership work
as before. Direct `add-user.yml` calls require the equivalent list variable
`human_access_user_approved_groups` (default `[]`) before any mutation. Approval is
operator acceptance, not automatic Linux permission analysis; re-review after server
configuration changes. Existing users/groups are not migrated. `none` adds no sudo
fragment and verification requires no non-interactive sudo grant.

`add-user` accepts a pasted public key or `HUMAN_PUBLIC_KEY`; it never generates
a private key. `generate-user-key` prompts for a passphrase. Directories are private (`0700`), and private
keys are `0600` or stricter. Existing pairs are preserved; partial pairs, symlinks,
unsafe permissions and reuse of the automation-key path fail. The wrapper never
reads private-key bytes or uploads them. Existing encrypted human keys can use
an already unlocked SSH agent, with `IdentitiesOnly=yes` and the selected identity;
managed automation can also use its selected key through that agent. Public-only imports report **UNVERIFIED**
when the matching private key is unavailable locally. They cannot authorize final
hardening. Use a separate key for each person and protect backups like passwords.
`secrets/` and common key filenames are excluded from Git and Docker contexts;
ignore rules are a guard, not a substitute for reviewing staged files. Never put secrets
or public keys in inventory or committed configuration. Only `show-public-key`
explicitly displays the public key for transfer; private key contents are never printed.

### Common preflight failure

The stock `operator` account may already have a system group with GID 37, which
conflicts with creating a fresh human account of the same name. The former generic
preflight message hid this diagnosis. Choose an unused `HUMAN_USER`; do not delete
or adopt existing users, groups, homes, sudo fragments, records or keys blindly.
An already generated `operator` key remains preserved. From the retained recovery
session, an operator can inspect the account and sudo validator:

```bash
getent passwd operator
getent group operator
sudo -n /usr/sbin/visudo -c
sudo -n namei -l /usr/sbin/visudo
```

Symlinks remain unsupported. Do not replace distro binaries to bypass preflight;
report the diagnosis for a separate compatibility review.

The role reuses bootstrap account/controller-key tasks, preserves other
`authorized_keys`, protects the home/SSH files and validates sudo candidates with
`visudo -cf`. Existing unmanaged accounts/groups, unsafe homes, conflicting sudo
fragments, orphan records and privilege-policy changes fail before mutation.
Completed accounts have root-owned records under `/var/lib/portfolio-human-access/`.
Adding groups/keys is supported; deletion, account adoption, privilege-policy
migration and removal of existing keys/groups require separate reviewed work.
An interrupted account creation without a completion record requires recovery
inspection rather than automatic adoption. Re-running the same successful command
preserves keys and converges account state without replacing access.

`secure-ssh` re-verifies the selected **admin** and `ansible_user`, including fresh
key-only connections and non-interactive root sudo, before default-deny interactive
recovery confirmation. The role also rechecks both identities immediately before
policy work. It installs `PermitRootLogin no`, `PasswordAuthentication no` and
`KbdInteractiveAuthentication no` in a separate managed block after the Stage 3
port block, before standard includes. Ports, firewall and activation mode are
preserved. All `Match` blocks and unsupported Include trees fail closed. A complete
snapshot, syntax validation, effective-policy comparison and source fingerprints
precede atomic installation; only the three authentication settings may change.
Validated `ssh.service` reload applies authentication in service and socket modes
without restarting listeners. Unchanged configuration does not reload the service.

After activation, independent administrator/automation SSH and sudo checks repeat
on every selected route. Read-only verification checks effective policy and probes
SSH authentication methods against existing host trust, rejecting advertised
password/keyboard-interactive methods. Root denial is proved by effective global
policy with conditional exceptions refused; no root credential is used for a
negative login test. Runtime probes cover every selected verification route;
server listener checks still require all `ssh_listen_ports`.

On any error, stop; policy may already be installed. Do not close the retained
session or retry blindly. `/etc/ssh/portfolio-security.pending` blocks subsequent
application/verification if installation or reload was interrupted. Through the
retained sudo administrator session or tested provider console, inspect the
managed block, source files and pending receipt, run `sshd -t` and check `sshd -T`,
then explicitly reload the reviewed configuration and verify fresh access. Remove
the pending receipt only after confirming recovery/convergence. Restoring a needed
fallback policy is an explicit console recovery decision, never automatic rollback.
After hardening, add more users with the same `add-user`/`verify-user` commands
through `ansible_user`; no password/root fallback is re-enabled. Existing Stage 3 and
maintenance commands preserve this final block. Application deployment remains a
separate stage.

Manual validation order: run `make check` offline (including new synthetic/mocked
Stage 4 regressions), inspect the code and local inputs, then explicitly approve
live Stage 3 verification, `add-user`, `verify-user`, `secure-ssh`, and
`verify-ssh-security` in that order. Repeat creation and secure operations to assess
idempotency, then add/verify another ordinary user after hardening. Exercise failures
(denied confirmation, bad key, unmanaged account, conflicting sudo, Match/include,
interrupted activation) only on disposable fixtures or a recoverable test VPS.

## Server operations and maintenance (Stage 5)

Run Stage 5 separately after Stage 4. Application deployment remains separate.
`inspect-operations` and `verify-operations` use strict key-only OpenSSH, existing
host trust and `sudo -n`; they stream standard-library Python through stdin with
`-I -B`, without remote payload files, cache updates, package refreshes, smoke
containers or journal writes. Normal SSH/sudo audit records may still be generated.
All commands first inspect Stage 3 hardening; Stage 5 also requires the Stage 4
final root/password/keyboard-interactive policy. Only the current inventory SSH
route is used; use Stage 3/4 verification separately to re-prove all routes and
human administrator access.

| Command | Behavior |
| --- | --- |
| `make inspect-operations` | LIVE/read-only preflight; PASS/WARN are ready, FAIL blocks |
| `make setup-operations` | LIVE/mutating; preflight then TTY confirmation `[y/N]`, default deny |
| `make verify-operations` | LIVE/read-only; require installed policy, packages, timers and limits |
| `make preview-apt-policy` | LIVE/check-diff; preview only the exact missing APT policy line |
| `make apply-apt-policy` | LIVE/mutating; guarded APT-only replacement after default-deny TTY confirmation |

For the diagnosed missing `Unattended-Upgrade::Remove-New-Unused-Dependencies
"false";` directive, use the separate APT-only entry point. It reuses strict
managed SSH/sudo, existing host trust and Stage 3/5 inspectors. Preview and apply
each require separate LIVE authorization:

```bash
make preview-apt-policy INVENTORY=inventories/production.yml
# Only after reviewing the preview and separately authorizing application:
make apply-apt-policy INVENTORY=inventories/production.yml
make verify-operations INVENTORY=inventories/production.yml
```

The destination must already be a root:root regular file with mode 0644 and
trusted parent paths. Its bytes must match the current `apt-security.j2` template
exactly, or differ only by that one missing line. A wider diff, unsafe metadata,
concurrent replacement or lock contention stops the command without attempting
repair. Preview uses Ansible `--check --diff` and does not write the managed APT
file; Ansible may create temporary execution files. Apply replaces only
`/etc/apt/apt.conf.d/99zz-portfolio-security` atomically and runs existing Stage 5
verification. An already matching file is unchanged. This path does not install
packages or configure Docker, journald, timers, SSH, sudoers or accounts.
If application or subsequent verification fails, the APT file may already have
changed: stop, inspect read-only and do not retry blindly. `setup-operations`
retains its broader scope and must not be used as an APT-only repair.

Setup installs `unattended-upgrades` and `logrotate` with `state: present`, without
an immediate package-index refresh or upgrade. It manages one marked APT file,
clears inherited origin allowlists and permits only Ubuntu's release-specific
`-security` origin. Docker's third-party origin, normal `-updates`, ESM and other
origins are excluded. Automatic reboot and automatic package/kernel removal are
disabled. Enabled `apt-daily`, `apt-daily-upgrade` and `logrotate` timers perform
scheduled work later; overdue timers may run shortly after setup. Security updates
can restart affected services through package maintainer scripts. Keep recovery
access and choose a maintenance window. Package installation needs usable cached
APT indexes and network access; failures stop without automatic recovery.
Already-running APT maintenance services block policy transitions; wait for
completion and inspect again rather than deleting lock files.

Journald defaults: persistent journal cap 256 MiB, runtime cap 64 MiB, 512 MiB
reserved free space, retention 14 days and compression. Role defaults in
`roles/server_operations/defaults/main.yml` parameterize these bounds; operational
variables do not belong in the restricted inventory. Only a changed journald file
notifies its restart handler. Repeat unchanged setup should report `changed=0`;
this has to be confirmed on your VPS. Existing journals age out during normal
rotation; setup never vacuums or deletes them. Limits are per journal namespace
and do not cap arbitrary application files. Non-default journal namespaces are
outside this stage.

System logrotate must have a finite global rotation count (1–52); entries may
override it with 0–52. Only the standard `/etc/logrotate.d` include is supported.
Preflight reports exact escaped configuration paths and expected/actual state.
Missing role-owned files and the journald drop-in directory are WARN before setup
and FAIL during verification; unsafe existing files, ancestors or symlinks always
FAIL. Native `apt-config` validates installed syntax and effective values; the
prospective configuration is replayed through stdin in APT load order, with the
managed file inserted at its actual position and the main `apt.conf` last. No
hooks, shell commands or package operations are executed. Hash comments, scopes,
lists, regex and unrelated vendor hooks are handled by APT itself. There are no
filename-based policy exceptions: standard periodic settings such as those in
`10periodic` can coexist if the candidate converges safely. Late/main overrides,
unknown policy controls, unsafe reboot/removal/authentication settings,
uninspected includes and redirected configuration sources block setup.
The stock `Unattended-Upgrade::DevRelease` controls whether unattended upgrades
run on a development release; it does not authorize additional origins or upgrade
the distribution. On identified stable Ubuntu (including Noble 24.04 LTS),
`auto`, `false` and `true` are valid. Unknown values, nested controls, missing or
conflicting release identity fail closed. Development releases are unsupported:
`auto` may enable updates near release day, `true` enables them, while `false`
disables them and therefore cannot satisfy Stage 5 security-update guarantees.
Both installed and prospective APT policy are checked with the same release
classification from `/etc/os-release` and optional `/etc/lsb-release`.
Independent journald settings such as `ForwardToSyslog` coexist; unmanaged
retention controls and unknown/invalid settings remain blocking. Reports expose
paths, key names and line numbers without configuration values or command text.
Preflight also refuses unsafe/symlinked managed paths, masked/custom
maintenance units or drop-ins, failed critical services, incomplete dpkg state,
and low disk/inode headroom. Configurations that fail must be reconciled manually;
setup never resets or adopts unrelated files. It verifies system logrotate in
`--debug` mode without rotating or changing its state file. Stage 2 Docker
`local` logging with `20m`/`5` is required in the daemon and every existing
container; existing containers keep their creation-time logging settings and
must be reviewed/recreated separately if incompatible. No Docker restart, prune,
network, public port or external monitoring service is added.

Diagnostics show load per CPU, available RAM, swap use, free disk/inodes for `/`,
`/var`, `/var/log`, `/var/lib/docker`, SSH/socket, Docker/containerd, journald,
timers, failed units, effective update policy and journal limits. Disk below
10% or 512 MiB, or inodes below 5%, blocks setup. RAM below 15%, load/core above 1,
swap above 50% or absent swap produce WARN. Reboot-required and APT/update-run
stamps older than three days also produce WARN: stamps show scheduling activity,
not proof that every security update installed successfully. Inspection is a
snapshot using cached metadata; it does not refresh indexes, simulate an upgrade,
count outstanding security packages, install updates or schedule monitoring.
Service health means systemd state, not application availability. Probe timeout
or malformed state fails closed; raw command stderr/configuration/logs are hidden.

Manual verification sequence (not executed during implementation):

```bash
make deps               # if local pinned tools are not installed; registry access
make check              # offline regressions, lint and example-inventory syntax
# Only after reviewing code, local inventory, keys and provider recovery access:
make inspect-operations
make setup-operations   # explicitly confirm in the terminal
make verify-operations
make setup-operations   # confirm again; expect changed=0 with no drift
make verify-operations
```

These commands support existing `INVENTORY` and `AUTOMATION_KEY` overrides. Do not
use a live `--check` as an offline test. Stage 5 adds no automatic reboot: when
reboot is pending, separately approve `make reboot-host`, then repeat
`make verify-operations`; reboot-host's existing verification includes a Docker
smoke container and may populate the image cache.

Recovery is manual. If SSH fails, stop retries and use the provider console.
Inspect `systemctl status ssh.service ssh.socket --no-pager`, `sshd -t`,
`sshd -T`, `ss -lnt` and `ufw status verbose`; compare Stage 3 ports and Stage 4
policy before any edit/reload. Preserve an open recovery session and verify
managed and human key-only access independently before leaving it. Never restore
root/password login or reset UFW as an automatic fallback.

For Docker, use console or verified admin access to read
`systemctl is-active docker containerd` and `docker info --format '{{.LoggingDriver}}'`.
Review storage headroom and known-good Stage 2 daemon configuration before an
explicitly approved repair. Do not delete `/var/lib/docker`, uninstall runtimes,
prune resources or blindly restart Docker. For an administrator, inspect `id
<admin>`, `getent passwd <admin>` and `visudo -c` through console/managed access;
restore only a reviewed public key/account/sudo configuration. Do not copy private
keys or adopt an unmanaged account automatically; re-prove `make verify-user`
and `make verify-ssh-security` with the existing `HUMAN_*` inputs. A missing
managed account requires the separately approved bootstrap/recovery workflow.

For update/log diagnostics, `systemctl is-active apt-daily.timer
apt-daily-upgrade.timer logrotate.timer`, `systemctl --failed --no-pager`,
`dpkg --audit`, `journalctl --disk-usage` and `logrotate --debug
/etc/logrotate.conf` are read-only probes. Run them only in an explicitly approved
live session; review verbose/debug output locally because it can expose paths or
other sensitive details. Never run logrotate without `--debug`, force APT/dpkg
lock removal, run autoremove, vacuum journals or trigger upgrades as a diagnostic.

## User and SSH key management (Stage 6, task 3)

These commands contact the VPS through the inventory managed user and private-key path.
They never use the initial password login or require a hardcoded automation username.
Listing reads actual server accounts, groups, effective sudo/SSH policy and authorized keys;
there is no local user/key cache. Root and the current controller cannot be targeted.

| Command | Purpose | Boundary |
| --- | --- | --- |
| `make list-users` | List recorded human users/rights/keys and the protected inventory controller | LIVE / read-only |
| `make show-user HUMAN_USER=operator` | Inspect identity, groups, sudo and SSH keys | LIVE / read-only |
| `make list-user-keys HUMAN_USER=operator` | List authorized public keys, SHA256 fingerprints and ownership | LIVE / read-only |
| `make add-user-key HUMAN_USER=operator HUMAN_PUBLIC_KEY=/path/other-pc.pub` | Add one public key, preserving every other entry | LIVE / MUTATING, interactive confirmation |
| `make revoke-user-key HUMAN_USER=operator KEY_FINGERPRINT=SHA256:...` | Revoke exactly one managed key | LIVE / MUTATING, retained admin proof and confirmation |
| `make remove-user HUMAN_USER=operator` | Revoke credentials/sudo and delete the account, retaining files | LIVE / MUTATING, retained admin proof and confirmation |

Public imports use the existing `.pub` validation; private keys are never uploaded or read.
Importing from another PC does not require its private key on this controller. After an
addition, the key owner must independently verify login with that identity, for example
`make verify-user HUMAN_USER=operator HUMAN_SUDO=admin HUMAN_KEY=/path/operator-key`
from a configured checkout on that PC. Import success alone does not prove access.
Existing-user `add-user` uses the same additive key engine; existing privilege/group
changes are refused and require a separately reviewed migration.

Account ownership comes from protected `/var/lib/portfolio-human-access/<user>.json`
records, checked against the current identity and privilege policy. Exact authorized-key
entries explicitly installed through these wrappers are tracked in adjacent
`<user>.keys.json` records. Existing keys from earlier stages are shown as unmanaged.
To take responsibility for one, explicitly add its identical public line (including its
comment) using `add-user-key`; a matching fingerprint with different options/comments or
multiple entries blocks the operation. Unmanaged accounts cannot be adopted; unmanaged
keys cannot be revoked, and any unmanaged key blocks account removal. These server
records establish ownership, while actual VPS state remains the source of access facts.

Human-key registration rejects every identity currently authorized for the controller,
including legacy keys and keys with different comments/options. The check runs locally
for the selected controller key and on the server for its complete supported key set.
Direct `add-user.yml` calls enforce identity checks and removal receipts; they only
create fresh accounts. Existing accounts must use `make add-user` / `make add-user-key`
so registration uses the locked additive engine without changing privileges, groups or
existing key options. Direct `secure-ssh.yml` calls also check server-side identity
independence. Certificate-authority entries and alternate controller authorization
sources are unsupported and fail closed.

For revocation/removal, supply another managed human administrator and its local key:

```sh
make revoke-user-key HUMAN_USER=operator KEY_FINGERPRINT=SHA256:... \
  RECOVERY_USER=backupadmin RECOVERY_KEY=~/.ssh/portfolio-infra/backupadmin_ed25519
make remove-user HUMAN_USER=operator \
  RECOVERY_USER=backupadmin RECOVERY_KEY=~/.ssh/portfolio-infra/backupadmin_ed25519
```

The retained administrator must differ from the target and current controller. Its
key identity must also differ from the controller key; copying that key to another
path does not qualify. Target and recovery accounts must have disjoint sets of all
current key fingerprints, including unmanaged entries and entries with SSH options.
The selected, freshly proven recovery fingerprint must remain authorized and must not
match any server-authorized controller key. OpenSSH verification ignores client
configuration, additional
identities, proxies and forwarding; only the selected identity may use the human's
existing agent. Key paths cannot contain OpenSSH expansion tokens. Managed automation
uses the same selected-agent policy; load encrypted controller keys before running targets.
The recovery keypair must be local, complete and protected with the same permissions
as other human keys; unlock an encrypted recovery key in your agent before verification.
Fresh key-only SSH and `sudo -n` access are proven on every `ssh_verify_ports` route.
Without that proof the last confirmed human administrative access cannot be removed.
Keep provider-console recovery available. Mutations verify Stage 3 and managed access,
show the current state/request, require default-deny TTY confirmation, and reject state
changes after preflight. Server-side operations serialize and check key contents before
atomic replacement. Target/controller snapshots and recovery proof are rechecked after
staging the replacement, immediately before rename; destructive operations also recheck
recovery after credential changes and stop on drift without rollback or retry.
The management lock serializes this engine's mutations, not external root or user edits
to user-owned SSH directories. Those edits may still race after the last check; the
operation is not a filesystem/account transaction. Fresh-account creation is a separate
multi-task Ansible operation: serialize operator runs and inspect interrupted creation
rather than automatically adopting or repairing it. No SSH daemon, ports, authentication
policy or services are changed.
A successful mutation checks its exact server result and re-proves managed access.

Removal blocks active user processes, custom userdel hooks, unknown privilege/group state,
conditional SSH Match policies, unsupported key sources/includes and pending SSH activation.
It empties authorized keys and removes the managed sudo fragment before invoking
`userdel` without `--remove` or `--force`. Home, mail and other user files remain with their
numeric ownership; a protected removal receipt prevents automatic account recreation.
Do not reassign that UID to another account without reviewing the retained files.
Repeated add/revoke/removal is unchanged when the verified result already exists.
Revoking a key affects future authentication, not an existing SSH session.
If a mutation fails, credentials may already have been revoked: stop and inspect through
retained administrator/provider recovery access; never retry blindly or reopen SSH policy.

Offline checks cover ownership boundaries, preservation, exact revocation, stale proofs,
confirmation, retained files, strict transport and Make wrappers. Live operator checks
remain necessary: import keys from two PCs, verify each identity independently, revoke
one and prove new login fails while the other succeeds, remove a disposable managed
account and confirm its files remain, then check repeated operations and Stage 1–5 access.

## Stage 6 integration: manual LIVE checklist

Offline validation does not establish VPS access or live idempotency. Run these steps
only as separately approved operator operations, with a tested provider console and
retained admin session. Use disposable usernames/keys for revocation and removal.

1. **Baseline and migration.** Keep the old ignored inventory and verify its access.
   On a secured VPS, follow [the candidate-inventory migration](#managed-user-configuration-and-migration):
   create the new admin through `add-user`, verify it, then run `verify-access` against
   the candidate inventory. Keep the current ports and SSH policy. Password bootstrap
   belongs only to a fresh VPS with its initial login still available.
2. **Local identities and trust.** On each PC run `make setup`, create a separate key
   with `generate-user-key`, and display its public member with `show-public-key`.
   Verify host fingerprints independently before recording local trust. Use passphrases
   and `load-user-key` for human/recovery/controller keys; one encrypted device key can serve interactive SSH and managed automation.
   Transfer only `.pub` files. `show-controller` must display that PC's intended inventory
   user/key. Missing trust or a conflicting key override must stop access.
3. **Second controller and sudo.** Through the first controller, add the second PC's
   public key to a separate managed admin with `add-user`/`add-user-key`. On PC 2, verify
   its candidate inventory with `verify-access`; independently verify the human admin
   with `verify-user HUMAN_USER=… HUMAN_SUDO=admin HUMAN_KEY=…`. In `connect-controller`
   and `connect-user`, check `id -un` and `sudo -n id -u` (admin result: `0`). Both PCs
   must continue working without copying private keys or relying on the other's agent.
4. **Exact keys and recovery refusal.** Add two PC keys to a disposable human account,
   inspect them with `list-user-keys`, and verify each from its owner PC. Repeat the add:
   expect `changed: false`. With a separate proven `RECOVERY_USER`/`RECOVERY_KEY`, revoke
   one fingerprint. A fresh session with it must fail, while the other key, controller
   and recovery admin still work. Repeat revocation: expect unchanged. A wrong/unloaded
   recovery key, missing sudo, copied controller key, target/controller recovery username
   or declined confirmation must leave target state untouched. Existing sessions survive
   key revocation; test with fresh connections.
5. **Removal and files.** Create a marker file under the disposable user's home and
   close its sessions/processes. Register any legacy key by its identical public line
   before removal. Remove it using the separate recovery proof, then verify absent
   account/sudo, empty authorized keys, preserved marker/home with numeric ownership,
   unchanged recovery/controller access and an unchanged repeated removal. Recreation
   must fail. Busy accounts and unmanaged keys must block removal before revocation.
6. **Stage 1–5 regression and STOP.** From both candidate inventories run `verify-access`,
   `verify-docker`, `verify-hardening`, `verify-ssh-security` with the retained human admin,
   and `verify-operations`, in that order. Docker verification may populate its image
   cache. Only after success deliberately select the candidate inventory. Repeated
   provisioning and `changed=0` checks require separate approval; do not reboot or rerun
   password bootstrap as a regression check on a secured VPS.

Both controllers use the same protected server ownership records; there is no local
ledger to synchronize. Protection applies to root and the current inventory controller;
the server cannot discover other PCs' candidate inventories. Keep every active controller
out of deletion tests, and retain a separate verified human admin. Unmanaged legacy
automation accounts cannot be removed through these commands. If key installation
succeeds but ledger writing fails, the new entry remains unmanaged: inspect through
recovery, then explicitly register its identical public line. A failure after credentials
or sudo were revoked requires manual recovery inspection, without blind retries.
