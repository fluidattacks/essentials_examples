# Fluid Attacks Essentials — Example Repository

This repository is a sandbox for testing and demonstrating the [Fluid Attacks Essential plan](https://fluidattacks.com/plans/). It contains intentionally vulnerable code and configuration files to benchmark the scanner suite, and a GitHub Actions workflow that mirrors a real trunk-based development pipeline.

> **All secrets and credentials in this repository are dummy values for benchmarking purposes. Do not use them in any real environment.**

## Purpose

- Validate that each Fluid Attacks GitHub Action (SAST, SCA, DAST, Secret Scan, CI Gate) detects the expected findings.
- Demonstrate how the scanners integrate into a trunk-based development workflow with pull request checks.
- Serve as a reference for configuring the actions in customer repositories.

## Vulnerability examples

Each file or directory below contains at least one intentional finding to exercise a specific scanner.

## GitHub Actions integration

The workflow at `.github/workflows/dev.yml` runs the full Fluid Attacks scanner suite on every pull request. It is split across two triggers to handle secrets correctly for fork PRs:

| Trigger | Jobs |
|---|---|
| `pull_request` | `sast`, `sca-scan`, `dast-scan`, `secret-scan` |
| `pull_request_target` | `ci-gate` |

The `ci-gate` job runs on `pull_request_target` because GitHub withholds secrets from `pull_request` workflows triggered by fork PRs. The CI Gate only calls the Fluid Attacks API and never checks out or executes PR code, so this is safe.

## Trunk-based development workflow

This repository follows a trunk-based development model:

- `main` is the trunk. It is always in a releasable state.
- All work happens on short-lived feature branches cut from `main`.
- Every branch is merged back to `main` via a pull request — no long-lived branches.
- The PR checks (SAST, SCA, DAST, secret scan, CI Gate) act as the quality gate. A branch cannot be merged if the scanners find policy-breaking issues.

This model keeps the feedback loop short: findings are surfaced at PR time, before any vulnerable code reaches the trunk.

## More information

- [Fluid Attacks platform](https://app.fluidattacks.com)
- [Fluid Attacks documentation](https://docs.fluidattacks.com)
