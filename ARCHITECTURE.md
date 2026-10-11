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
| `cli.py` | Argument parsing, command dispatch, umask and sanitized top-level errors. |
| `common.py` | Repository root, default automation key path, SSH policy constants and validation guards. |
| `inventory.py` | Exclusive inventory creation, static inventory validation, access selection and hardening port inputs. |
| `keys.py` | Key path/metadata validation, public key parsing and identity comparison, locked non-overwriting generation and temporary public snapshots. |
| `local_keys.py` | Local human key selection, generation/show/copy/load commands and loading the selected identity into the invoking shell's existing agent. |
| `clipboard.py` | Public-material clipboard backend selection and explicit local tool installation prompts. |
| `host_trust.py` | Initial bootstrap trust, endpoint-bound JSON transfer, atomic known_hosts imports and signed cross-port host identity proof. |
| `ssh.py` | Interactive controller/human SSH commands and host-bound probes of offered authentication methods. |
| `ansible.py` | Controller prerequisites and pinned playbook execution using a temporary inventory overlay. |
| `inspection.py` | SSH stdin transports for hardening/operations inspectors and the remote user-management engine. |
| `verification.py` | Independent managed and human Ansible access verification over selected ports. |
| `provisioning.py` | Bootstrap/access, Docker, hardening and separately confirmed reboot orchestration. |
| `human_access.py` | Human policy inputs, confirmed public-key registration, account creation/additive access and final SSH security orchestration. |
| `user_management.py` | User queries and mutations, including fresh independent recovery access proof and confirmation. |
| `operations.py` | Operations inspection/setup/verification and separately confirmed APT policy preview/application. |
| `compat.py` | Isolated flat helper namespaces for legacy file-based imports of `access.py`. |

Dependencies are explicit relative imports and form an acyclic graph. `common`
has no package dependencies. `keys`, `ansible` and `inspection` depend only on
`common`; `inventory` adds `keys`. `clipboard` uses `keys`; `host_trust` uses
`inventory`, `keys` and `clipboard`. `local_keys` uses `keys` and `clipboard`;
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

Each command dispatches only its existing stage sequence. Initial password
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

## State and security invariants

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
importer's own namespace. It reconstructs the two contextmanager wrappers so
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
