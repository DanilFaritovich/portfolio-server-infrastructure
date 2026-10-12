# Architecture

This repository provisions an Ubuntu portfolio VPS from a local controller. The
controller owns Ansible, inventory, SSH identities and host trust. The VPS runs
the selected playbooks and streamed Python payloads; it does not run the CLI
package. Application deployment is separate. Operator commands and recovery
procedures are documented in [README.md](README.md) and
[README.ru.md](README.ru.md); agent rules are in [AGENTS.md](AGENTS.md).

## Controller modules

Make targets and `scripts/setup.sh` invoke `scripts/access.py`. This compatible
entry point runs `portfolio_cli.cli.main()` from `scripts/portfolio_cli/`, with
the same commands, arguments, output formats and exit codes.

| Module | Responsibility |
| --- | --- |
| `cli.py` | Argument parsing, locked server command dispatch, umask and sanitized failure/interruption errors. |
| `common.py` | Repository root, default automation key path, SSH policy constants and validation guards. |
| `plans.py` | Default-deny plans, snapshots of inputs/implementation, bounded nested consent and anonymous E2E child grants. |
| `inventory.py` | Exclusive inventory creation, static inventory validation, access selection and hardening port inputs. |
| `keys.py` | Key path/metadata validation, public key parsing and identity comparison, locked non-overwriting generation and temporary public snapshots. |
| `local_keys.py` | Local human key selection, generation/show/copy/load commands and loading the selected identity into the invoking shell's existing agent. |
| `clipboard.py` | Public-material clipboard backend selection and explicit local tool installation prompts. |
| `host_trust.py` | Initial bootstrap trust, endpoint-bound JSON transfer, atomic known_hosts imports and signed cross-port host identity proof. |
| `ssh.py` | Interactive controller/human SSH commands and host-bound probes of offered authentication methods. |
| `ansible.py` | Controller prerequisites, local pipeline serialization and pinned playbook execution using a temporary inventory overlay. |
| `inspection.py` | SSH stdin transports for hardening/operations inspectors and the remote user-management engine. |
| `verification.py` | Independent managed and human Ansible access verification over selected ports. |
| `provisioning.py` | Bootstrap/access, Docker, hardening and separately confirmed reboot orchestration. |
| `human_access.py` | Human policy inputs, confirmed public-key registration, account creation/additive access and final SSH security orchestration. |
| `user_management.py` | User queries and mutations, including fresh independent recovery access proof and confirmation. |
| `operations.py` | Operations inspection/setup/verification and separately confirmed APT policy preview/application. |
| `compat.py` | Isolated flat helper namespaces for legacy file-based imports of `access.py`. |

Dependencies are explicit relative imports and form an acyclic graph. `common`
has no package dependencies. `plans` depends on `common`. `keys`, `ansible` and
`inspection` depend only on `common`; `inventory` adds `keys`. `clipboard` uses
`keys` and `plans`; `host_trust` uses `inventory`, `keys` and `clipboard`.
`local_keys` uses `keys`, `clipboard` and `plans`;
`ssh` uses `inventory`, `keys`, `local_keys` and `host_trust`. `verification`
uses `ansible` and `keys`.

The stage modules compose these lower-level services. `human_access` also uses
`ssh` authentication probes and shared `verification`; `user_management` uses
shared `verification` without importing human stage orchestration. `cli` imports
the command handlers. Lower layers do not import `cli`, `compat` or stage
orchestration. Shared transport code deliberately retains the distinct timeout,
output validation and failure behavior of each existing inspector.

## Execution flows

The provisioning sequence remains:

```text
local setup -> password bootstrap -> managed access verification
-> Docker host -> Docker verification
-> firewall/SSH hardening -> hardening verification
-> human access -> human verification
-> final SSH policy -> SSH security verification
-> separately confirmed server operations -> operations verification -> STOP
```

`init-server` is the whole-pipeline exception: `initialization.py` calls existing
stage functions directly under the CLI's single lock, without nested CLI/Make
invocations. An operator-selected `INIT_FROM` frontier authorizes remaining
applications; earlier stages must pass their independent verifiers before being
skipped. `verify` selects verification only. A failed verifier never establishes
absence or authorizes mutation. Remaining stages use existing preflight/postflight
and an explicit verifier at every dependency boundary; Stage 3 also runs its streamed
inspector before application. No provisioning roles or recovery logic are duplicated.

Initialization requires a TTY and prepared human admin key. One default-deny plan
confirmation covers the listed remaining stages in this invocation, including the
provider-console recovery attestation for final SSH policy. Read-only preflight
may precede consent; confirmation occurs before the first planned change. Native
password/passphrase, sudo and host-trust prompts remain separate.
Errors, pending state, interruptions and log-write failures stop later dispatch.
Continuation requires recovery diagnosis and explicit frontier selection, never
log-based checkpoints, retry or rollback. Exclusive temporary JSONL files (0600)
store only schema, fixed stage/status and monotonic elapsed seconds for the named
stage (`run` events use whole-run time). Applying stages emit `applying` then
`verifying` before `completed` or `failed`; verified skips retain `verified_skip`.
Logs exclude output, exception text, inventory and identities. Terminal failures
retain exact allowlisted static causes or safe process/I/O categories and the active
command, never arbitrary exception text or raw stderr. EOF at frontier selection
or plan confirmation cancels before mutation without traceback; preflight may
already have contacted the host.
These are diagnostic records,
not authority over server state. The terminal shows progress and verified stages
while retaining existing stage diagnostics and native authentication prompts.

`plans.py` stores authority only in a ContextVar for the active call stack. Nested
plans can narrow authority and bind additional snapshots, never expand it. Input
or implementation drift stops dispatch; errors reset the scope. Standalone changes
use the same `Apply this plan? [y/N]` prompt. Exact read-only evidence permits
hardening, final SSH policy, operations and managed-key registration to skip
application when unchanged. Terminal public-key registration still confirms before
host contact; explicit public-file automation retains its existing contract.
Local setup compares pinned tool/collection readiness before offering downloads
and inventory creation. Existing inventories are preserved without reading them.

Other commands dispatch only their existing stage sequence. Initial password
bootstrap uses `bootstrap_login_user`; managed paths select `ansible_user` and
`ansible_private_key_file`. Explicit inventory access requires all three fields
together and rejects conflicting key overrides. Legacy inventories retain their
initial-login/default-managed-key behavior.

Managed mutations first prove key-only access and passwordless sudo. Port
verification opens fresh independent connections for every selected
`ssh_verify_ports` entry while preserving the already trusted host identity.
Reboot requires a separate default-deny confirmation and bounded recovery,
followed by access, Docker and hardening verification in order. Failure stops
later checks.

Docker provisioning also runs independent Docker verification before reporting
completion. Its disposable smoke test can populate the image cache and reports
runtime changes even when the provisioning role itself is unchanged.
Both smoke creation and attached execution bound the Docker client to 120 seconds
plus a 10-second forced-termination grace. Start/cleanup require a successful create
and a full 64-character hexadecimal ID. Timeout does not prove daemon-side
cancellation; missing/unconfirmed IDs require diagnosis without guessed cleanup.

Human registration validates and snapshots explicitly supplied public material
before host contact. New accounts use the Ansible human role; existing managed
accounts use the additive remote engine. Final SSH security proves managed and
independent human admin access before the recovery confirmation and candidate
activation, then verifies access and runtime authentication policy.

User queries and mutations use `inspection.user_probe`. Destructive requests
require a fresh separate human-admin SSH/sudo proof, distinct key identities,
an unchanged server snapshot and default-deny confirmation. The remote engine
owns its locks, key ledgers and removal receipts; the controller holds no local
ownership cache.

Operations commands stream hardening and operations preflight before setup.
Setup and APT application have separate confirmations; preview retains
check/diff mode. APT application changes only the narrowly validated existing
APT file and runs operations verification afterward. Partial failure requires
STOP and read-only diagnosis, with no automatic retry or rollback.

Local key and host-trust transfer commands are separate from account
provisioning. Trust export/source import need no user private key or host
contact. Optional destination/cross-port proof performs a signed host-only
exchange and requires its own default-deny confirmation before saving trust.

## SSH and Ansible boundaries

`ansible.run_playbook` runs the project's pinned `.venv/bin/ansible-playbook`,
uses the caller's inventory plus a private temporary JSON connection overlay,
and passes non-connection role variables as extra vars. The overlay contains
paths and connection settings, never passwords or private key contents, and is
removed after child execution. Only initial bootstrap uses the pinned builtin
Paramiko password transport through `plugins/connection/portfolio_password.py`;
managed Ansible paths use OpenSSH.

`inspection.py` runs strict key-only OpenSSH, checks the expected login identity,
and streams repository payload source through stdin to `sudo -n` and isolated
Python (`-I -B`). It does not copy payloads or create remote cache files. The
hardening and operations paths stream read-only inspectors; user queries and
mutations stream the existing user engine with explicit parameters. That
engine can mutate managed state only for authorized mutation requests.

`library/`, `scripts/user_management.py`, Ansible roles and playbooks retain
their server-side responsibilities. The CLI package is never uploaded as a
replacement for those payloads. SSH daemon/socket activation, firewall policy,
Docker preflight and operations policy remain implemented in those components.

The Stage 3 socket inspector distinguishes the effective on-disk candidate,
PID 1's loaded properties, inherited live descriptors and desired routes.
On disk, a supported generated `addresses.conf` resets the package listeners;
without it, only the two reviewed Ubuntu port-22 package defaults are accepted.
The package's binding policy normalizes disk routes independently of loaded
state. Candidate validation requires desired disk routes before restart;
postflight and reload scheduling compare all normalized IPv4/IPv6 route sets.
Read-only findings expose the selected source and normalized wildcard routes,
never raw configurations or command output. Receipt handling is unchanged.

## State and security invariants

Server CLI commands hold a non-blocking exclusive `flock` on the current user's
`~/.portfolio-infrastructure.pipeline.lock` throughout preflight, confirmation,
execution and postflight. The same lock covers different inventories, ports and
repository checkouts for that user. Unsafe lock metadata or contention fails
before dispatch; the stable inode is never unlinked. Process exit releases this
local lock, including interruption. Local key/trust commands and interactive SSH
sessions remain independent so recovery access remains available.

This lock does not coordinate other controller users/machines, direct Python
handler calls or raw Ansible. Operators must serialize those paths manually.
The remote key engine keeps its own snapshot-bound server lock, now failing
immediately on contention instead of queuing a mutation that might start after
the caller's transport timeout. Existing SSH/APT module locks and snapshots
retain their narrower scopes; there is no host-wide transaction.

Docker, Stage 3 SSH listeners and journald now use pending activation markers.
Ansible previews the managed file with check mode, records pending state before
an intended file change and activates through existing handlers. SSH also records
pending state for legacy adoption and socket convergence. The marker is cleared
only after activation and its server postflight succeed. SSH handler postflight
uses the internal `activation_check` option to run strict runtime checks while
retaining the marker; ordinary inspection/verification refuses pending state.
Pending final SSH policy also blocks Stage 3 and its consumers, preventing an
unrelated stage from activating an incomplete authentication change. Final SSH
handlers use that internal allowance for source inspection while retaining their
existing exact-policy/fingerprint/receipt check before reload and receipt
completion afterward.
Docker checks the active logging driver, and journald checks service activity;
independent controller/operations postflight still follows. Journald's effective
configuration probe reads disk policy, not an introspection of the running
daemon's complete configuration.

Markers are fail-closed recovery evidence, not rollback instructions or ownership
records. Failure before the file write can leave a conservative pending marker;
failure after successful activation but before receipt cleanup can do the same.
Recovery requires inspecting approved disk policy, service state and access before
deliberately clearing that exact marker. Neither multiple file writes nor the
whole pipeline is atomic. These receipts do not guarantee power-loss durability
or protect changes by unrelated root processes.

SSH failure, timeout or interruption leaves remote execution unconfirmed and may
leave a remote operation running. Dependent checks stop; the CLI never retries,
rolls back or interprets local lock release as remote completion. Hardening SSH
stdin probes now have bounded login/payload timeouts like operations/user probes.
Temporary Ansible overlays are cleaned on handled failure and interruption;
uncatchable controller termination can still leave a private temporary overlay.

| Pipeline | Failure/repetition boundary |
| --- | --- |
| Bootstrap | Public-input and sudo-path preflight; additive account/key/sudo tasks followed by independent managed login/sudo. No whole-account transaction. |
| Docker | Package/configuration/data safety preflight; activation receipt and independent runtime verification. Installed packages remain present on partial failure. |
| Host hardening | Protected UFW base/rule snapshots and bounded additive recovery; validated SSH adoption/listener receipts, ordered activation and fresh route verification. |
| Human creation/addition | Server ownership/privilege preflight, protected records and additive engine postflight. Partial fresh creation is refused as unmanaged/orphan state; no adoption or rollback. Public imports remain access-unverified. |
| Final SSH policy | Fresh independent managed/human proofs, confirmation, exact staged sources and protected activation receipt. An incomplete policy cannot be activated by another normal stage. |
| Operations | Read-only hardening/operations preflight, native effective APT policy checks, journald activation receipt and operations postflight. No reboot/prune/vacuum rollback. |
| APT-only repair | Exact approved bytes/metadata, module lock and unchanged snapshots; narrowly scoped replacement followed by operations verification. |
| User keys/removal | Server lock, fresh target/controller/recovery snapshots, staged key replacement and postflight. Ledger-write failure requires explicit identical-line registration; userdel failure after revocation requires recovery diagnosis. Homes are retained. |
| Reboot | Fresh managed access/sudo and default-deny confirmation; bounded reboot/reconnection, then access, Docker and hardening in order. No retry on unknown reboot state. |

- Actual inventories remain local and ignored; the committed inventory is an
  example. Setup never overwrites an existing inventory.
- Private key material is never read by Python or uploaded. Python validates
  metadata; native OpenSSH tools own generation, signing and passphrase input.
  Keys are never overwritten, and unsafe ownership, permissions, symlinks and
  OpenSSH path expansion tokens block access.
- Managed OpenSSH uses key-only authentication, BatchMode, IdentitiesOnly,
  strict host checking, no client-config overrides and no forwarding. Only the
  selected agent identity is eligible; the CLI never starts a child agent.
- Host trust is bound to the exact host/port. Imports preserve unrelated
  entries, reject conflicts/marked or unsafe trust and use locking plus atomic
  unchanged-snapshot replacement. Cross-port proof authenticates the host
  without user authentication or remote commands; it never replaces keys.
  Initial bootstrap trust requires an explicit provider/admin fingerprint
  comparison and confirmation; a scan alone does not prove identity.
- Local public snapshots are private and temporary. Clipboard transfers contain
  public keys or validated public host-trust JSON only. Terminal registrations
  require default-deny confirmation before host contact.
- Human/controller/recovery identities remain independent. Unmanaged accounts,
  keys and privileges are not adopted. Supplementary groups require exact
  explicit approval after rights review. Protected remote ledgers, receipts,
  token validation and staging locks remain owned by the server engine;
  external account/SSH edits and multi-task fresh creation remain outside its
  transaction lock.
- SSH hardening preserves recovery access and the existing listener activation
  mode until the separately verified final policy stage. Ambiguous unmanaged
  policy or state blocks changes. No fallback downgrade, automatic account
  adoption, unrelated configuration reset, package removal, prune or blind
  retry is introduced.
- Expected errors are sanitized at the CLI/transport boundaries. Existing
  command exit codes remain 0 for success, 1 for handled failures and 2 for
  argument parsing errors. Payload report and JSON formats are unchanged.

## Import compatibility and offline verification

Tests and other file-based consumers can load `access.py` under arbitrary module
names without registering it in `sys.modules`. `compat.install` exports the
original helpers and globals, binding the existing function code to each
importer's own namespace. It reconstructs the public contextmanager wrappers so
their underlying generators also use that namespace. Legacy attribute mocks
therefore affect only that imported instance, leaving package functions and
other imports independent. No function source is duplicated or dynamically
executed by the adapter. CLI execution bypasses the adapter and uses normal
package module globals; new native tests patch the consuming module's imports.

`make check` is offline: lint, example-inventory syntax validation, workflow
validation and synthetic-fixture tests with mocked remote execution. Existing
tests cover the legacy imports; `tests/test_cli_package.py` additionally checks
native dispatch, failure ordering, port verification, confirmations, isolated
mocking and CLI invocation outside the repository. The clean setup fixture
copies the package with its entry point. Offline success does not establish
LIVE access, remote idempotency or recovery readiness; those remain separately
authorized operator checks.

## Local VM integration boundary

`scripts/e2e.py` invokes `portfolio_cli.e2e`: a separate controller lifecycle for
one per-user KVM BIOS guest and dedicated NAT on `qemu:///system`. It uses virsh
XML queries, virt-install XML generation, checked official Ubuntu cloud image,
minimal cloud-init bootstrap and stopped internal qcow2 snapshots. `e2e_images`
validates the declarative image registry and rejects redirects before following;
`e2e_readiness` bounds output-free read-only probes over the local QEMU agent
channel. New fixtures install/start the guest agent through cloud-init; this
does not create SSH trust or change the controller's packages.
`e2e_host` validates Linux x86_64/KVM/libvirt capabilities without host release
allowlists. It handles only explicitly confirmed missing packages through a reviewed
Ubuntu/Debian apt mapping, additive groups and exclusive dedicated directory
creation. Configured but ineffective groups return `REBOOT_REQUIRED`; the CLI
releases the fixture lock before offering reboot now/later and exits successfully
without fixture creation. Before a separately confirmed request, `e2e_host` selects
one backend using local session capabilities: complete GNOME X11/Wayland uses
`gnome-session-quit --reboot`; other supported Linux/systemd sessions use systemctl
with explicit inhibitor checks and no authentication prompt. Incomplete GNOME,
remote/root/unsupported sessions and missing tools use manual instructions.
There is no force, sudo, OS-version selection or second-backend retry. Static
failure classification avoids printing child stderr; even a zero exit with stderr
is unconfirmed because GNOME may swallow D-Bus failures. Uncertain completion
requires diagnosis before any manual retry; desktop confirmation remains native.
A fresh prepare revalidates permissions; group errors remain fail-closed.
Unreadable root-owned QEMU configuration may receive separately confirmed
read-only sudo inspection by isolated system Python. An unchanged file snapshot
and stock identities are required; no configuration bytes are printed and no
file permissions are changed. Failure stops before storage/VM creation.
Unsupported installers require manual dependencies; prepared hosts
continue only after capability/access/storage checks. Guest profiles stay strict. Neither implements
provisioning or recovery. Schema-2 state records the distro; schema-1 Noble fixtures
remain readable without migration. The lifecycle module
owns fixture state/locking, resource validation and the interactive scenario;
it does not implement provisioning. See [the operator guide](docs/local-vm-e2e.md).

The fixture lives outside the repository, with a private HOME, inventory,
identities, trust and temporary records. Fixed per-user disk paths live under
`/var/lib/libvirt/images/portfolio-e2e-<UID>`. State UUIDs plus namespaced domain
and network metadata and exact device/path validation establish ownership.
New disk sources disable only DAC relabeling to preserve controller ownership:
the qcow2 grants its protected storage group read/write access (0660), while
the read-only seed uses 0640. Only the exact owned qcow2 may pass the group-write
exception; legacy fixtures are not rewritten or repaired.
Successful list queries alone establish absence; query errors and partial state
never authorize recreation. Prepare journals `preparing` before artifacts and
marks `ready` only after a console-verified stopped baseline. After explicit
console-check and shutdown consent, prepare revalidates resources and allows up
to 300 seconds for UUID-bound cloud-init/SSH/logind/Power Button readiness before
requesting graceful shutdown. One short guest probe is tracked at a time, with
only exit codes collected; identity/guest/protocol errors stop, and only an
explicit agent-disconnected boot response permits transport polling. Shutdown
then waits up to 120 seconds before baseline creation. Legacy fixtures are not
equipped with an agent automatically or resumed after failed preparation.
Destructive actions validate
paths/snapshots and foreign users before and after default-deny consent,
use graceful shutdown and never force unsupported restoration.

The scenario launches existing `make init-server` and `make reboot-host` children.
The eight `e2e-` user-management Make wrappers dispatch the existing access CLI
under the same fixture lock and guard. An explicit allowlist forwards human policy,
selected key paths and recovery inputs; operator key paths become absolute before
switching HOME. Inventory/controller identity and trust remain fixture-owned.
User operations retain native confirmations and recovery proofs, without scenario
consent grants or VM lifecycle actions.
Before importing CLI transports, `access.py` invokes the E2E guard for these
children: revalidate resources, bridge route/DHCP, exact inventory and fixed child
inputs, then pin OpenSSH fixture trust. Paramiko uses isolated HOME. Production
execution and legacy imports do not activate this guard. The scenario's single
plan covers key generation, selected initialization, repeat convergence and guest
reboot. An inherited anonymous pipe transfers consent to exactly one guarded child
invocation, bound to its mode/frontier and input snapshot; no persistent receipt or
general environment yes switch exists. Child policy inputs explicitly include
Make's exported empty values and defaults before snapshotting; missing and empty
remain distinct. Key generation receives the fixture inventory explicitly. The
guard rejects changed fixed policy inputs before sanitizing the environment, and
snapshots bind key selection and the Make recipes as well as CLI/role code.
Offline regression tests traverse GNU Make, the inherited descriptor and the real
CLI guard/plan receiver with VM proofs and operation dispatch mocked.
Roles, independent proofs and native
authentication/host-trust prompts remain. Numeric Ansible recaps or exact managed
no-op evidence prove repeat provisioning is unchanged (with the verifier's exact
three Docker smoke changes); independent SSH probes and boot IDs cover persistence.
Errors preserve state and diagnostic snapshots; continuation remains explicit.
Offline mocked lifecycle tests join the existing unittest discovery; check/CI
never depend on VM targets. Real compatibility/idempotency remain operator tests.
