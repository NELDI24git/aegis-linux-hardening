# Changelog

## v1.1.0 — 2026-10-27

- Added schema-versioned snapshots of complete audit findings with policy fingerprints, optional host IDs and repeatable scope metadata.
- Added text and JSON snapshot diffs that classify added/removed checks, resolved findings, regressions and other changes.
- Rejects host or scope mismatches; signed snapshots fail closed and verify the exact bytes parsed.
- Added atomic, no-overwrite snapshot creation with optional HMAC sidecars and stable exit code 9 for finding changes.
- Shared the safe artifact publisher between baselines and snapshots; added tests and CLI/documentation coverage.

## v1.0.0 — 2026-10-27

- Stabilized the 1.x command-line, exit-code, policy and evidence-format compatibility contract.
- Added a contract test covering public schema versions, stable exit codes, SARIF version and the legacy SSH remediation entry point.
- Documented compatibility rules, supported evidence formats and the disposable-system validation workflow.
- Updated release metadata, man page, integration guidance and package smoke checks for v1.0.0.

## v0.10.0 — 2026-10-27

- Added SARIF 2.1.0 audit output with stable rule IDs, severity, evidence and remediation metadata.
- Added optional, validated repository-relative SARIF location maps for GitHub Code Scanning; Aegis does not invent code locations for host findings.
- Signed baselines now fail closed when a signature exists but no verification key is supplied; `--require-signature` can reject unsigned inputs.
- Baseline comparison verifies and parses the same captured bytes, validates record shapes/ranges, and refuses silent overwrite without `--force`.
- Added atomic output writes, exclusive integrity-key creation, signature schema v2 with filename-bound HMAC (while retaining v1 verification), and focused lifecycle/SARIF tests.
- Expanded safe evidence handling and SARIF interoperability.


## 0.9.0

- Release-candidate milestone.
- Added report schema v2 and baseline schema v2 metadata.
- Added disposable Ubuntu/Debian/Fedora container harness.
- Added GitHub Actions Python 3.10-3.13 unit matrix, packaging smoke and manual container matrix.
- Added destructive mixed-domain injected-failure rollback test.
- Added policy/profile/exception, integrity, schema, event-log and stable-exit-code tests.
- Wheel build + clean-venv installation verified.
- End-to-end signed audit/baseline/fix/rollback fake-root flow verified.

## 0.8.0

- Added HMAC-SHA256 integrity key/sign/verify workflow for reports and baselines.
- Added structured JSONL operational event log.
- Added stable automation exit codes.
- Added system install/uninstall scripts, bash/zsh completion and man page.
- Integrity keys require restrictive permissions and cannot be symlinks.
- Event logger refuses symlink target files.

## 0.7.0

- Added `general`, `web-server`, `database`, `bastion`, `container-host` and `minimal` profiles.
- Added inherited public-port role intent with local overrides.
- Added semantic control tags and profile/tag filtering.
- Added policy schema v3 control include/exclude fields.
- Added time-bounded exceptions with rationale/expiry/ticket metadata.
- Added `EXEMPT` status preserving original result and excluding accepted exceptions from score.

## 0.6.0

- Added Debian/Ubuntu and RPM-family platform adapters.
- Abstracted package provenance, firewall and automatic-update semantics.
- Added systemd hardening advisory checks and writable custom-unit detection.

## 0.5.0

- Generalized remediation engine beyond SSH.
- Added mixed-domain atomic transactions and managed sysctl fixes.
- Added runtime rollback restoration/validation and lockout-sensitive SSH preflight.

## 0.4.0

- Added baseline/drift detection, transaction SHA-256 conflict checks, transaction history, doctor and CI fail threshold.

## 0.3.0

- Added PAM/kernel/mount/logging/time/container checks and HTML report.

## 0.2.0

- Added attack-surface inventory, firewall/Fail2Ban/update review and inventory caching.

## 0.1.0

- Initial modular audit engine, SSH/account/filesystem checks, scoring and transaction prototype.
