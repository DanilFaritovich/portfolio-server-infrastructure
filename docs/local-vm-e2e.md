# Local Ubuntu VM E2E

This is an **interactive local integration test**, outside `make check` and CI.
It uses KVM, `qemu:///system`, virt-install, a registry-selected official Ubuntu
amd64 cloud image and cloud-init. virt-manager can inspect the same guest. GNOME Boxes is not used.
No application deployment is included. Offline success does not demonstrate live
access, package compatibility, snapshot support or idempotency.

## Host preparation (explicit operator consent)

Host eligibility depends on capabilities: **Linux x86_64**, hardware virtualization,
working QEMU/KVM and system libvirt, required tools, permissions and safe storage.
There is no host Ubuntu release allowlist. At least 2 available CPU cores, 4 GiB
guest RAM and sufficient disk space for a 25 GiB qcow2 disk, the cloud image and
internal snapshots are required. Guest support remains restricted to the registry
profiles below; accepting a host does not add Guest OS support.
Run `make deps` first to prepare the project's local Python tooling; never run
`make` as root.

System hypervisor tools run without the controller virtualenv/Python environment
in their subprocess environment. In particular, `/usr/bin/env python3` in
virt-install must resolve the host Python with distro-provided gi/libvirt modules;
the controller and scenario Ansible commands retain their pinned tooling.

`make e2e-prepare` checks CPU virtualization flags, installed packages and commands,
`/dev/kvm` access, effective libvirt/kvm groups, non-sudo `qemu:///system` access,
x86_64 KVM capabilities and disk directory ownership/mode. Host changes occur only
for a new fixture, with separate default-deny TTY confirmations:

1. Missing dependencies are listed before offering `sudo apt-get update` and
   `sudo apt-get install --no-install-recommends --no-upgrade --no-remove` for
   **only missing packages**. The reviewed package mapping is selected only when
   os-release identifies Ubuntu or Debian and both apt-get and dpkg-query exist,
   without restricting release numbers. An apt executable or ID_LIKE alone does
   not establish compatibility. The package set is qemu-system-x86,
   qemu-utils, libvirt-daemon-system, libvirt-clients, virtinst, cloud-image-utils,
   openssl, iproute2 and openssh-client. Installed packages are not reinstalled;
   installed packages with missing executables require manual PATH/package repair.
   Native sudo and apt prompts remain interactive. Failure stops without retry.
   Other managers, unknown OS metadata or missing apt/dpkg tools never trigger
   automatic installation: missing commands are listed with manual installation
   instructions. A manually prepared host may continue without package-manager
   support if all tools and subsequent capability/access/storage checks pass.
   No distribution-specific package names are guessed for unsupported managers.
2. Missing libvirt/kvm membership is offered separately, using only additive
   `usermod -aG`. **libvirt access is root-equivalent**; grant it only to trusted
   local administrators. If configured groups are not effective in this session,
   prepare finishes successfully with a reboot-required result, before disk/VM
   creation. An interactive menu offers **Reboot now** or **Reboot later**:

   ```text
   ✓ Host permissions configured successfully.
   A system restart is required to activate new permissions.

   [1] Reboot now (recommended)
   [2] Reboot later

   Choose [1/2]:
   ```

   Reboot now prints `After rebooting, run: make e2e-prepare`, warns about unsaved
   data and requires a separate default-deny `[y/N]` confirmation. After releasing
   the fixture lock, the CLI selects **one** backend from local session capabilities,
   without consulting OS versions:

   - Local GNOME X11/Wayland: `gnome-session-quit --reboot`, keeping the desktop's
     normal confirmation and inhibitor handling. GNOME is an exact colon-separated
     token in `XDG_CURRENT_DESKTOP`; only when that is unset, a GNOME-specific
     `XDG_SESSION_DESKTOP` value can identify it. The corresponding display variable
     (`DISPLAY` or `WAYLAND_DISPLAY`) and a Unix session D-Bus address are required.
     Incomplete GNOME sessions or a missing tool receive manual instructions;
     they never fall through to systemctl.
   - Other local Linux/systemd sessions: `systemctl --check-inhibitors=yes
     --no-ask-password reboot`. The systemd runtime directory and systemctl must
     exist, and the session type must be a supported graphical/console type or unset
     for a plain local terminal. System authorization and inhibitors are respected
     even with captured subprocess output.

   Root, non-Linux, SSH and remote/ambiguous `XDG_SESSION_REMOTE` sessions are
   refused. There is no sudo, force, inhibitor bypass or automatic second backend
   after failure. GNOME may show another desktop confirmation; a successful tool
   exit only means a request, not completed reboot.

   Failures show a short static reason: missing tool/session capability,
   inhibitor, authorization, unsupported option, unavailable session/system service,
   execution error, timeout or interruption. Child diagnostics are classified in
   English without printing raw stderr, identities, paths or terminal controls.
   Unrecognized diagnostics report the exit status and a generic safe reason.
   GNOME can return zero after a failed D-Bus call; stderr still makes the outcome
   unconfirmed. A timeout, interruption or other unconfirmed result cannot prove
   cancellation: inspect system state before any manual retry. Use the desktop's
   normal Restart action or ask the administrator to restart safely.
   Reboot later, an empty choice, declined confirmation or interrupted input preserves
   configured groups and exits successfully with the rerun instruction. Without a TTY,
   only manual instructions are printed. There is no unattended restart.

   After rebooting, rerun `make e2e-prepare` (repeat `E2E_DISTRO` if selected).
   It freshly checks effective groups, KVM/libvirt access and storage, then proceeds
   with the existing confirmations; no extra permission commands are needed.
   Group setup errors or unverified membership still fail closed. Effective groups
   do not trigger this menu. No guest or fixture state is created before permissions
   become active.

3. The missing `/var/lib/libvirt/images/portfolio-e2e-<UID>` directory is offered
   separately. Exclusive `mkdir` refuses a concurrently appearing path; only this
   new directory receives controller ownership, stock `libvirt-qemu` group and
   mode 2750. The final chmod also uses sudo: an owner outside the QEMU group
   cannot retain setgid with an unprivileged chmod. Parent paths must already
   be protected root-owned directories. Existing ownership/group are never repaired.
   For the empty dedicated directory left by the earlier chmod bug, prepare may
   separately offer finishing mode 0750 to 2750 within the same command. It requires
   the correct controller/QEMU ownership, no symlinks or access ACL, and an unchanged
   directory snapshot and empty contents after confirmation. No existing fixture,
   VM data, other mode or ownership/group drift receives this exception.

The setgid directory gives generated files the QEMU group. New qcow2 disks use
0660 for QEMU read/write access; seed ISOs use 0640 for read-only access. Both
disk sources carry `seclabel model="dac" relabel="no"`, so libvirt does not change
their controller ownership. AppArmor remains enabled. Group write is accepted
only for the controller-owned qcow2 with mode 0660 and the protected storage
directory's group; seed files and other paths retain the stricter checks.
Existing fixtures are not rewritten or repaired. Custom QEMU identities, unsafe paths, missing parent directories,
KVM/device permission errors, libvirt authorization/service errors or host security
policy conflicts require manual administrator diagnosis. The existing libvirt/kvm
group and stock libvirt-qemu storage conventions still apply; accepting a Linux
host does not automatically migrate its hypervisor configuration. Preparation does not
change libvirt configuration, start services, relax AppArmor/ACLs or grant sudo.
A declined confirmation leaves later steps unexecuted; already approved package
or group changes are retained. No automatic rollback or cleanup is attempted.

Preparation inspects `/etc/libvirt/qemu.conf` to reject custom QEMU identities
before disk creation. If the controller cannot read this root-owned file,
`make e2e-prepare` offers a separate default-deny read-only sudo inspection.
Authenticate at the native sudo prompt within the same command. The isolated
system Python interpreter verifies file safety, unchanged identity/content
metadata and stock QEMU user/group settings without printing configuration.
No ACL, ownership or permission changes are needed. Declining, failed sudo,
custom identities or concurrent file changes stop preparation before disk/VM
creation; no default identity is assumed after a failed read.
CLI failures report the operation and safe OS error categories (for example,
`E2E STOP (fixture lock)` with `EROFS` indicates a read-only filesystem or
controller sandbox). Failed subprocesses also name a fixed operation (such as
network activation or domain XML generation) and exit status, without arguments
or child output. These diagnostics do not prove cancellation or authorize retry.
Arbitrary exception text, paths and subprocess output are
excluded. Diagnose controller restrictions before requesting a new run; they
do not establish a VM or libvirt failure.

Optional graphical inspection remains a manual operator action (`virt-manager`).
A ready existing fixture is freshly validated and displayed without host changes,
downloads or guest recreation. Partial fixtures stop without resuming preparation.

## Prepare and first run

After separately authorizing real local VM execution:

```sh
make e2e-list-distros  # local registry listing, no host/network probes
make e2e-prepare      # Ubuntu Server 24.04 LTS by default
# Alternative for a NEW fixture:
# make e2e-prepare E2E_DISTRO=ubuntu-22.04
make e2e-status
make e2e-test E2E_FROM=bootstrap
```

Defaults: 2 vCPU, 4096 MiB RAM, 25 GiB qcow2, dedicated NAT
`192.168.231.0/24`, DHCP-reserved guest `192.168.231.10`, SSH port 22.
For a new fixture only, set `E2E_CPUS`, `E2E_MEMORY`, `E2E_DISK_GB`,
`E2E_SUBNET` (an unused private `192.168.x.0/24`). Minimum resources remain
2/4096/25. Existing fixtures retain their recorded settings; prepare does not
resize/reconfigure/recreate them. Host-route and libvirt-network overlap blocks
creation. NAT provides outbound Internet for existing APT/Docker operations;
it is a separate bridge, not an outbound sandbox or air gap. Do not place
production credentials in the guest.

The declarative [image registry](../scripts/portfolio_cli/e2e_distros.yml) supports
only **Ubuntu Server 24.04 LTS (`ubuntu-24.04`)** and **Ubuntu Server 22.04 LTS
(`ubuntu-22.04`)**, both amd64. It records display identity, architecture, official
image/checksum URLs and reviewed BIOS/qcow2/cloud-init/SSH compatibility profiles.
Other Linux distributions, architectures, UEFI images and release versions are
rejected. Jammy and Noble are allowed by the current provisioning roles; both use
the same root-password cloud-init bootstrap and stock SSH service/socket handling.
The conservative `ubuntu22.04` virt-install hardware profile works with both and
is available in Jammy controller osinfo-db; it does not change the guest image.
Mocked tests cover both selections; real package/SSH/convergence compatibility
still requires separately authorized integration runs on each version.

New state (schema 2) records the selected distro, shown by `e2e-status`. Existing
schema-1 fixtures retain their original Noble identity without state rewrites.
Omitting `E2E_DISTRO` for an existing fixture keeps its recorded distro. A different
explicit selection blocks; only separately confirmed deletion permits preparation
of another image. It never overwrites an existing VM.

Images and SHA256SUMS come only from the official HTTPS release directories:
[Ubuntu Noble](https://cloud-images.ubuntu.com/releases/noble/release/) and
[Ubuntu Jammy](https://cloud-images.ubuntu.com/releases/jammy/release/).
Strict registry validation rejects untrusted URLs and incompatible profiles,
including duplicate YAML fields/IDs. Redirects are refused **before following**;
image transport ignores environment proxies. The complete downloaded SHA-256 is
compared with the official list and retained in `image.sha256`. Optionally set
`E2E_IMAGE_SHA256=<previously verified 64-character lowercase digest>` to require a
particular release digest. Mutable release URLs can change; any mismatch stops
preparation. The checksum list is authenticated by HTTPS, not an independently
verified GPG signature.

Prepare requests default-deny creation consent and a new disposable root
password twice with hidden input: at least 12 printable ASCII characters.
Short/non-ASCII input or a mismatch receives a specific safe message and repeats
local entry within prepare, before fixture/VM creation. Ctrl+C cancels; EOF or
interruption stops preparation. The password never enters argv, environment,
inventory, reports or Git. Only its SHA512-crypt hash enters private cloud-init
artifacts and the seed. Use a unique disposable password and keep it in your
password manager: the wrapper cannot display/recover it later. cloud-init only
establishes baseline root console/password SSH access and a fixture UUID marker;
all managed provisioning remains in existing Ansible roles.

Prepare starts the VM and prints its UUID and console command. In another
terminal, open `virsh -c qemu:///system console <UUID>` (or virt-manager serial
console), log in as root, and:

1. Run `cloud-init status --wait`; require successful completion with no errors.
2. Run `sshd -t`, `sshd -T | grep -E '^(permitrootlogin|passwordauthentication) '`
   and confirm both are `yes`. Check `systemctl is-active ssh.socket` or
   `systemctl is-active ssh.service` for the stock listener mode.
3. Run `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`; retain its fingerprint.
   Prove root console login works independently of SSH, then leave the console
   with Ctrl+]. Manual `poweroff` is not required.
4. Return to prepare and confirm both these checks and consent to shut down the
   guest and create the baseline. The wrapper revalidates the owned resources,
   requests graceful shutdown with `virsh shutdown` and waits up to 120 seconds
   for `shut off`. An already stopped guest needs no shutdown request; a guest
   already shutting down is only observed. No forced shutdown is attempted.
   Declining confirmation leaves the guest running. Timeout, an unexpected state
   or a query error stops preparation with the partial fixture retained.
   The wrapper creates/verifies an internal **baseline** snapshot, marks the
   fixture ready and starts it again. Wait for DHCP before testing.

An unsupported snapshot backend stops preparation with the partial fixture
retained. No fallback to a different backend or automatic repair is attempted.
The snapshot carries the complete owned domain definition, no memory state,
and only an internal qcow2 disk snapshot; see
[libvirt snapshot semantics](https://libvirt.org/formatsnapshot.html).

## Isolation and scenario execution

Resources are named `portfolio-e2e-<controller UID>`. Ownership requires recorded
UUIDs, namespaced libvirt metadata, fixed disk paths and the dedicated network.
Names alone never grant authority. Metadata and both persistent/runtime domain
XML are checked. E2E refuses extra disks, backing chains, passthrough devices,
external/memory snapshots, foreign network attachments and unsafe local paths.
A non-blocking sibling lock serializes fixture commands through all CLI children;
its inode survives deletion. Other libvirt administrators must manually serialize
operations; they can bypass this local lock.

Inventory, state, source image/cloud-init, keys, HOME, known_hosts and safe init
logs live under `~/.local/share/portfolio-e2e/` (outside the repository, private).
Only disks and seed live in the dedicated libvirt image directory. The inventory
is generated with explicit root bootstrap and managed `ansible` access; it is
not editable configuration. Exact inventory content, active owned VM/NAT,
matching MAC lease and host route through the owned bridge are rechecked before
CLI dispatch. `INVENTORY`, `AUTOMATION_KEY`, HUMAN_* and arbitrary Ansible overrides
from the invoking shell are excluded from E2E children; `E2E_INVENTORY` is refused.
CLI argument overrides and foreign inventories fail before provisioning.
The child pins the fixture known_hosts in OpenSSH and uses isolated HOME for
Paramiko. Production inventory/private material is never read by E2E.

`e2e-test` uses **real `make init-server`**, existing password bootstrap,
Ansible roles, independent key-only SSH/sudo, existing stage verifiers and all
registration/recovery/operations confirmations. It first generates the separate
`e2e_admin` human key with the existing local key workflow. It does not start an
agent. For encrypted keys, use the invoking shell's existing agent and accept
its native load prompt; for an existing unloaded identity run in that shell:

```sh
make load-user-key \
  HUMAN_KEY="$HOME/.local/share/portfolio-e2e/home/.ssh/human/admin_ed25519"
```

No SSH trust is auto-accepted. At first bootstrap compare the displayed
fingerprint against the VM console fingerprint before accepting trust. Keep
console recovery available during every stage and reboot. The root password
remains usable at serial console after final SSH root/password login is disabled.

The scenario performs:

- An operator-selected `INIT_FROM` frontier via `E2E_FROM` or the native prompt:
  fresh installation uses `bootstrap`; continuation uses an explicitly diagnosed
  frontier. Native earlier-stage verification remains mandatory.
- `init-server` verification of all stages; separate SSH probes check fixture
  UUID, managed identity, sudo, Docker active/enabled/runtime, UFW active,
  stock SSH listener, final root/password denial, maintenance timers and journald.
  Existing SSH security verification also probes offered authentication methods
  and independently proves human administrator access.
- Explicitly confirmed repeat convergence from `docker`, with native stage
  prompts. Streamed Ansible recaps require provisioning `changed=0`; the existing
  Docker disposable smoke verifier must report exactly its three deliberate
  container create/start/remove changes. No output log is saved by this parser.
  Missing/changed recaps fail the scenario; human additive behavior remains
  covered by existing verification and offline engine tests.
- Separately confirmed existing `reboot-host`, full final verification and
  independent probes again. Independently obtained boot IDs must differ.

Failures stop immediately, retain guest/local state and never reset/retry.
There is no automatic success report after a partial test. Sanitized native init
JSONL logs remain in the fixture's `tmp/`; they do not authorize continuation.
If output/probes fail, inspect console and the existing native read-only
inspectors. Do not clear pending activation markers/receipts or infer cancellation.

## Failure/recovery experiments (operator controlled)

Destructive experiments are intentionally manual: there is no auto-answer,
fault injection or automatic rollback mode. Run each from its own stopped
internal diagnostic snapshot, leaving baseline untouched. Use the UUID printed
by status, and inspect XML/console first. Example commands (operator actions):

```sh
virsh -c qemu:///system shutdown <UUID>
virsh -c qemu:///system domstate <UUID>  # must report shut off
virsh -c qemu:///system domblklist <UUID> --details
# Substitute the verified seed CD-ROM target (usually sda):
virsh -c qemu:///system snapshot-create-as <UUID> diagnostic-before-failure \
  --memspec snapshot=no --diskspec vda,snapshot=internal --diskspec sda,snapshot=no
virsh -c qemu:///system start <UUID>
```

Never use `--disk-only` (which selects external snapshots), `--force`,
`--running`, block-device/shared storage or snapshots of a running VM here.
Only `baseline` and `diagnostic-<lowercase-name>` stopped internal snapshots are
accepted by lifecycle validation. Supported experiments include interrupting a
stage, unavailable SSH during a stage and an existing pending marker. After
failure, use serial console and the relevant stage inspector, prove remote work
has stopped, document diagnosis, repair only the identified condition manually,
then select an explicit frontier, for example:

```sh
make e2e-test E2E_FROM=hardening
```

Earlier stages must freshly verify. Pending/ambiguous state still blocks.
For destructive policy or storage experiments, restore **their diagnostic**
snapshot manually only after console shutdown and inspection:

```sh
virsh -c qemu:///system domstate <UUID>  # shut off
virsh -c qemu:///system snapshot-dumpxml <UUID> diagnostic-before-failure
virsh -c qemu:///system snapshot-revert <UUID> diagnostic-before-failure
virsh -c qemu:///system domstate <UUID>  # must remain shut off
virsh -c qemu:///system start <UUID>
```

If revert/backend validation fails, STOP. Never force it or alter snapshot
metadata to conceal incompatibility. Independently diagnose before continuing.
Do not automatically reset after failed tests.

## Reset, deletion and incomplete preparation

```sh
make e2e-reset   # default-deny confirmation; graceful stop, baseline revert, start
make e2e-delete  # default-deny confirmation; delete only validated owned resources
```

Reset requires a ready fixture and verified baseline, gracefully stops the guest,
revalidates ownership and snapshots, reverts without force, checks it stays off,
then starts it. Local identities and baseline-compatible host trust remain.
Console password is the original baseline password. Timeout/paused guest or
unsupported backend blocks; no forced destroy.

Delete can remove a journaled partial preparation after explicit inspection and
confirmation. It validates all local paths before changes, rejects symlinks,
hardlinks, unknown storage files or another VM referencing the storage/NAT,
rechecks after confirmation, gracefully stops the owned guest, deletes its
validated snapshots, undefines it and removes only its dedicated NAT and files.
It never deletes shared pools/default networks, follows symlinks, uses wildcards
or `rm -rf`. The dedicated storage directory is also removed; a new preparation offers
its creation again with separate consent. The sibling lock inode is retained.
When its root-owned parent prevents unprivileged removal, delete requests an
additional default-deny sudo-rmdir confirmation before any mutation. Only the
validated empty dedicated directory is removed through sudo. Controller files
and state are retained until storage removal succeeds; no parent permissions
are changed and no extra shell command is required.
If deletion fails halfway, inspect actual resources; do not retry blindly.

A failed prepare retains phase `preparing`. Another prepare refuses to resume,
recreate or overwrite it. Use status/console to diagnose, then explicitly delete
only after ownership validation. Lost/invalid state, unknown resources or drift
require administrator diagnosis; matching names are insufficient for adoption.
Older fixtures may have QEMU-owned files left by libvirt's DAC relabeling,
including a read-only seed ISO after shutdown. These still block status/deletion;
the new XML policy applies only to new fixtures and does not repair existing
file ownership or resume partial preparation.
No secret cloud-init files or VM exports should be attached to public bug reports.
