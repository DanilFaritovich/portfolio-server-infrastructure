# Validation record

[English](validation.md) · [Русский](validation.ru.md) · [README](../README.md#real-world-validation)

## Real-world validation

The operator confirmed the following completed runs for this documentation update. No VPS or VM was contacted during documentation work. The original JSONL report was not independently opened; the production duration below is the value supplied by the operator from that report. Private inventory, host addresses, credentials, fingerprints and raw transcripts are intentionally not reproduced.

| Environment | Confirmed scope | Timing |
| --- | --- | --- |
| Separate Ubuntu VM through GNOME Boxes | Full E2E from scratch, including dependency preparation, infrastructure configuration, user management, SSH and SWAP | Not supplied |
| Real production VPS | All seven initialization stages: bootstrap, SWAP, Docker, SSH/UFW hardening, human access, final SSH security and operations; SSH on 2222; successful repeat verification and verification after reboot | **36 minutes 36.97 seconds**, from the reported initialization JSONL |

GNOME Boxes identifies the separate VM validation environment. The repository's automated fixture uses KVM/system libvirt, virt-install and cloud-init; it does not manage Boxes itself. The current [full and standalone scenarios](local-vm-e2e.md#isolation-and-scenario-execution) are documented from the implementation. No unreported VM release, nested topology, standalone-command transcript or per-check measurement is inferred from the latest confirmation.

The production timing describes initialization, not controller dependency installation, later verification, reboot or application deployment. The CLI records `elapsed_seconds` for each stage and whole-run time on `stage=run` events. For a successful run the terminal prints the path of a private temporary `portfolio-init-*.jsonl` file; the `run` / `completed` event is the total elapsed run time. It includes time spent in prompts during that run, but not plan/input preparation before execution starts. Do not sum stage events or interpret the log as automatic-resume evidence.

Production confirmation does not establish user deletion/revocation exercises, SWAP resize/disable cycles or repeat provisioning with `changed=0` there. Those are distinct VM scenario capabilities/results, not production guarantees. The report contains no production OS-release acceptance matrix, performance benchmark or availability guarantee.

## Earlier VM validation record

The earlier operator record identified an Ubuntu 26.04 controller and Ubuntu Server 24.04 LTS guest. [PR #11](https://github.com/DanilFaritovich/portfolio-server-infrastructure/pull/11) recorded offline checks, fixture preparation/initialization and an independent SSH/sudo/Docker/UFW/systemd/final-policy probe. That PR left complete repeat convergence and reboot pending after an earlier confirmation interruption. Later operator confirmation recorded final verification, repeat execution/idempotency, reboot persistence, user creation and verification, key addition/revocation, user removal and fixture deletion. These historical results do not specify the production environment or expand the latest VM report's platform details.

## Offline evidence and limits

`make check` validates YAML, offline Ansible lint, playbook syntax with the example inventory, GitHub Actions syntax and Python tests using synthetic fixtures and mocked external commands. [CI](../.github/workflows/ci.yml) installs dependencies with `make deps-ci` and runs `make ci` on Ubuntu 24.04. Offline success cannot prove remote access, provider-console recovery or live idempotency.

Docker smoke verification creates, runs and removes a disposable container and may populate the image cache. Those runtime effects are expected and are separate from provisioning convergence. A VM or VPS result does not prove all allowed Ubuntu releases, controller distributions/architectures or WSL2.

Reproduction requires separately authorized live operations and tested recovery access. Use the [operator guide](operator-guide.md#unified-initialization) for VPS deployment and the [E2E guide](local-vm-e2e.md) for owned fixtures. Preserve failed state for diagnosis; do not retry, reset or clear pending evidence automatically.
