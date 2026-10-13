# Validation record

[English](validation.md) · [Русский](validation.ru.md) · [README](../README.md#testing-and-recorded-results)

This record distinguishes implementation evidence from operator-reported integration results. It records the run supplied for the user guide; it does not claim a new live run during documentation work.

## Environment and evidence

| Component | Recorded environment |
| --- | --- |
| Main computer / controller | Ubuntu 26.04, according to the operator; no independent OS probe was performed for this documentation task |
| E2E guest | Ubuntu Server 24.04 LTS |
| GitHub Actions | Ubuntu 24.04, as configured in [ci.yml](../.github/workflows/ci.yml) |
| External production VPS | Not part of the confirmed E2E run |

[PR #11](https://github.com/DanilFaritovich/portfolio-server-infrastructure/pull/11) describes successful offline lint, Ansible syntax and Python checks, operator-confirmed VM preparation (`ready`, baseline present), initialization through all stages and an independent SSH/sudo/Docker/UFW/systemd/final-policy probe.

Its validation section also records an earlier repeat-convergence interruption at a hidden confirmation and leaves live validation of the fix, complete idempotency and reboot pending. The PR body is therefore evidence for preparation/initialization, not proof of every later scenario result.

The operator's subsequent confirmation supplied with this documentation task reports successful:

- Final verification, repeat execution and idempotency.
- Guest reboot and verification after reboot.
- User creation, SSH verification, key addition and revocation, and user removal.
- Safe deletion of the E2E fixture.

The [README results table](../README.md#testing-and-recorded-results) combines these sources with their provenance stated. No test count, transcript, private inventory or credentials are reproduced here.

## Interpretation and limits

Offline checks do not prove remote access or runtime behavior. A VM result does not establish acceptance on an external production VPS, every permitted Ubuntu release, other controller distributions/architectures or WSL2.

Repeat provisioning is expected to converge without managed configuration changes. Docker smoke verification still creates, runs and removes a disposable container and may populate the image cache; those runtime changes do not imply a provisioning idempotency failure.

Reproduction is a separately authorized real local operation. Follow the [E2E guide](local-vm-e2e.md), keep guest-console recovery and preserve failed fixtures for diagnosis. Production checks require their own authorization and recovery preparation.
