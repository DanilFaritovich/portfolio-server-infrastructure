# Local Ubuntu VM E2E

This is an **interactive local integration test**, outside `make check` and CI.
It uses KVM, `qemu:///system`, virt-install, Ubuntu Server 24.04 amd64 cloud image
and cloud-init. virt-manager can inspect the same guest. GNOME Boxes is not used.
No application deployment is included. Offline success does not demonstrate live
access, package compatibility, snapshot support or idempotency.

## Host preparation (operator actions)

Use an Ubuntu Linux amd64 controller with hardware virtualization enabled, at
least 2 available CPU cores, 4 GiB guest RAM and sufficient disk space for a
25 GiB qcow2 disk, the cloud image and internal snapshots. Check `/dev/kvm`.
These commands are instructions, **not automatically executed by E2E**:

```sh
sudo apt update
sudo apt install qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients \
  virtinst cloud-image-utils openssl iproute2 openssh-client
# Optional graphical inspection:
sudo apt install virt-manager
sudo usermod -aG libvirt,kvm "$USER"
# Log out/in to apply groups; verify access without sudo:
virsh -c qemu:///system list --all
```

The QEMU account/group is commonly `libvirt-qemu` on Ubuntu. Inspect the host's
libvirt configuration first. Create **only the new dedicated empty directory**
with your controller UID as owner and the actual QEMU group. Do not change
permissions of a shared image directory or run `make` as root:

```sh
sudo install -d -o "$USER" -g libvirt-qemu -m 2750 \
  "/var/lib/libvirt/images/portfolio-e2e-$(id -u)"
make deps
```

The setgid directory gives generated disk/seed files the QEMU group; files have
0640 permissions. QEMU must be able to traverse the path and the host security
policy must permit it. Resolve local permissions/AppArmor/libvirt authorization
manually; the wrapper never runs sudo or installs host packages. libvirt access
is root-equivalent: only trusted local administrators should have it.

## Prepare and first run

After separately authorizing real local VM execution:

```sh
make e2e-prepare
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

The image and its SHA256SUMS are fetched only from the official HTTPS
[Ubuntu Noble release directory](https://cloud-images.ubuntu.com/releases/noble/release/).
The wrapper compares the full downloaded image digest with the official list,
refuses redirects, and retains `image.sha256`. Optionally set
`E2E_IMAGE_SHA256=<previously verified 64-character digest>` to require a
particular release digest. The mutable release URL can change; a checksum
mismatch stops preparation. The digest list is authenticated by HTTPS, not an
independently verified GPG signature.

Prepare requests default-deny creation consent and a new disposable root
password twice with hidden input. The password never enters argv, environment,
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
   Prove root console login works independently of SSH, then run `poweroff`.
4. Return to prepare and confirm these checks. The VM must be shut off.
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
or `rm -rf`. The pre-existing dedicated storage directory is also removed; recreate
it explicitly for a new preparation. The sibling lock inode is retained.
If deletion fails halfway, inspect actual resources; do not retry blindly.

A failed prepare retains phase `preparing`. Another prepare refuses to resume,
recreate or overwrite it. Use status/console to diagnose, then explicitly delete
only after ownership validation. Lost/invalid state, unknown resources or drift
require administrator diagnosis; matching names are insufficient for adoption.
No secret cloud-init files or VM exports should be attached to public bug reports.
