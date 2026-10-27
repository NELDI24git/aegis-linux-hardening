# Roadmap

## v0.1 — core engine

Modular audit engine, initial SSH/account/filesystem controls, scoring/JSON and OpenSSH transaction prototype.

## v0.2 — attack-surface inventory

Listener + SUID/SGID inventory, sensitive service exposure, firewall/Fail2Ban/update review and collector caching.

## v0.3 — host hardening coverage

PAM, kernel, mounts, logging/audit/time, Docker and HTML reporting.

## v0.4 — drift and transaction safety

Baseline drift, policy-aware listener review, SHA-256 conflict-safe rollback, transaction history, doctor and CI severity threshold.

## v0.5 — remediation framework

Mixed-domain remediation, managed sysctl, runtime before/after state, post-rollback validation, SSH lockout preflight and policy schema v2.

## v0.6 — distribution adapters

Debian/RPM adapter families, package provenance, firewall/update abstraction and systemd security checks.

## v0.7 — role profiles and control packs

Completed: role profiles, inherited public-port intent, semantic tags, profile-based selection, local control overrides, and expiring exceptions represented as `EXEMPT`.

## v0.8 — operational hardening

Completed: install/uninstall workflow, bash/zsh completion, man page, structured JSONL event log, stable exit codes and HMAC-SHA256 report/baseline integrity.

## v0.9 — release candidate

Completed in code: report/baseline schemas, failure-path tests, packaging smoke, container harness, GitHub Actions unit/package/manual-container jobs, and end-to-end fake-root audit/baseline/fix/rollback coverage.

## v0.10 — evidence interoperability and lifecycle safety

Added SARIF 2.1.0 output, explicit repository location maps for GitHub Code Scanning, strict signed-baseline verification, baseline shape validation, no-overwrite-by-default baseline creation and atomic evidence writes.

## v1.0 — stable automation and evidence contracts

Released: stable 1.x CLI and exit-code behavior, versioned policy/report/baseline/transaction/event/signature formats, SARIF 2.1.0 output, compatibility tests, source and wheel packaging, and disposable integration procedures.

## Ongoing maintenance

- Run the unit and package workflow across supported Python versions for every change.
- Exercise remediation, service reload, lockout recovery, firewall behavior, sysctl persistence, package adapters, upgrades and rollback in disposable Linux environments before deploying those workflows to managed hosts.
- Add new CLI options and optional evidence fields compatibly; introduce a new schema version when a change breaks an existing consumer.
- Keep the compatibility matrix, security limitations and migration notes aligned with each release.
