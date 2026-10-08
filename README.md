# portfolio-server-infrastructure

[Русский](README.ru.md)

Host provisioning through Ansible for an Ubuntu VPS. The pipeline is:

```text
local setup -> bootstrap managed ansible user -> verify access
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

Edit only the hostname/address and existing SSH port for the standard path; `ansible_user` defaults to `root`. Keep the one-host `bootstrap` structure
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
an unrelated existing account as the managed `ansible` account.

## Access and security

The standard path is **root + interactive SSH password → ansible + dedicated
SSH key + NOPASSWD sudo**. Root is used only for initial bootstrap. Subsequent
provisioning must use `ansible`; `make verify-access` explicitly overrides the initial
inventory login with `ansible` and never uses a root password.

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
`/home/ansible/.ssh/authorized_keys`, preserving unrelated authorized keys.
Keep all SSH keys, real inventories, credentials and logs out of Git.

Public-key validation and reading run in an explicit controller-local block,
using the playbook's Python interpreter without sudo. Host/port come from the
local inventory. Runtime connection overrides are scoped only to the VPS alias
in a temporary inventory overlay (0600, removed after Ansible exits), rather
than global connection extra-vars; delegated localhost keeps its local context.
Only role inputs remain in `-e`. The overlay contains no passwords or key contents.

Generated keys have **no passphrase** for unattended provisioning. Possession of
this private automation key, together with unrestricted `NOPASSWD: ALL`, grants
**root-equivalent access to the VPS**. Protect the controller and key backups.
Running `make bootstrap-user` deliberately approves that policy; the role's default
consent remains `false`. A dedicated root-owned `/etc/sudoers.d/ansible` file uses
`0440` and is validated with `visudo -cf`. No login password is set for `ansible`.

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
and agent use disabled. Paramiko is limited to initial password-based bootstrap.
See [the pinned Ansible Paramiko transport documentation](https://docs.ansible.com/projects/ansible-core/2.18/collections/ansible/builtin/paramiko_ssh_connection.html).
The plugin is deprecated in newer Ansible releases and scheduled for removal in
2.21; re-evaluate initial password transport before upgrading Ansible to that version.

## Commands and boundaries

| Target | Purpose | Host access |
| --- | --- | --- |
| `make setup` | Install local dependencies; create missing local inventory | Dependency registries only |
| `make deps` | Install pinned local tooling/collections | Dependency registries only |
| `make bootstrap-user` | Create/reuse dedicated key, bootstrap account, then verify | **LIVE / MUTATING** |
| `make verify-access` | Verify existing key-only ansible access | **LIVE / verification**, no managed configuration changes |
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
key-only SSH connections as `ansible`. Verification checks Ansible ping,
`id -un == ansible` and `sudo -n id -u == 0`; every failed stage returns an error.
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
any Docker mutation it runs `playbooks/verify.yml`: login must be `ansible` and
`sudo -n` must reach UID 0. Missing keys fail with a `make bootstrap-user` hint;
failed login/sudo verification stops the stage. Docker tasks use per-task
privilege escalation with non-interactive sudo. `ansible` is never added to the
`docker` group. The inventory's initial administrator is overridden only for
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

Both public targets first verify existing independent `ansible` key-only access
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

The wrapper first verifies key-only SSH as `ansible` and `sudo -n` on the current
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

## Overrides and troubleshooting

Make accepts a local inventory path and an absolute private-key path outside the
repository. Use the same overrides for all live targets:

```bash
make bootstrap-user INVENTORY=/absolute/path/production.yml AUTOMATION_KEY=/absolute/path/dedicated/key
make verify-access INVENTORY=/absolute/path/production.yml AUTOMATION_KEY=/absolute/path/dedicated/key
make docker-host INVENTORY=/absolute/path/production.yml AUTOMATION_KEY=/absolute/path/dedicated/key
make verify-docker INVENTORY=/absolute/path/production.yml AUTOMATION_KEY=/absolute/path/dedicated/key
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
and the example's host, port, initial user, Python-interpreter and hardening port-list fields;
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
`AUTOMATION_KEY`; every command first verifies managed `ansible` key-only SSH,
`sudo -n`, and completed Stage 3 on every `ssh_verify_ports` route.

```bash
# Dedicated Ed25519 key generated locally; root-equivalent NOPASSWD administrator.
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
make add-user HUMAN_USER=reader HUMAN_GROUPS=readers HUMAN_SUDO=none \
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
Root/system and common runtime privilege groups are refused; `sudo`/`admin` groups
require the admin policy. Review custom group privileges separately. `none` adds
no sudo fragment and verification requires no non-interactive sudo grant.

Generated keys have no passphrase, directories are private (`0700`), and private
keys are `0600` or stricter. Existing pairs are preserved; partial pairs, symlinks,
unsafe permissions and reuse of the automation-key path fail. The wrapper never
reads private-key bytes or uploads them. Existing encrypted human keys can use
an already unlocked SSH agent, with `IdentitiesOnly=yes` and the selected identity;
automation remains agent-independent. Public-only imports report **UNVERIFIED**
when the matching private key is unavailable locally. They cannot authorize final
hardening. Use a separate key for each person and protect backups like passwords.
`secrets/` and common key filenames are excluded from Git and Docker contexts;
ignore rules are a guard, not a substitute for reviewing staged files. No secret
or public key belongs in inventory, command output or committed configuration.

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

`secure-ssh` re-verifies the selected **admin** and `ansible`, including fresh
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
through `ansible`; no password/root fallback is re-enabled. Existing Stage 3 and
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
