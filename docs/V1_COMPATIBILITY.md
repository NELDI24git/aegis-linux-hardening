# Aegis v1 compatibility contract

This document defines the automation-facing compatibility guarantees for Aegis 1.x. The command-line interface and versioned machine-readable formats are stable within the 1.x major version. Internal Python modules are implementation details; the supported programmatic interface is the `aegis` command.

## Compatibility rules

- Existing commands, options, exit-code meanings and documented output fields keep their meaning throughout 1.x.
- New commands, optional arguments, checks, rules and optional output fields may be added compatibly.
- A change that removes or changes the meaning/type of an existing CLI contract element requires a new major version.
- A breaking change to a machine-readable format increments that format's `schema_version`; readers reject unsupported future schemas instead of silently misreading them.
- Policy migration is explicit. Aegis never silently activates a migrated or invalid policy.
- Transaction rollback validates transaction data and current file state before modifying files; conflict protection remains part of the remediation contract.

## Versioned formats in 1.0.0

| Interface or format | Current version | Compatibility behavior |
| --- | ---: | --- |
| CLI automation exit codes | 1.x contract | Numeric meanings listed below are stable. |
| Policy | schema 3 | Legacy input migration is an explicit `policy migrate` operation. |
| JSON audit report | schema 2 | Consumers should inspect `schema_version`. |
| Baseline | schema 2 | Schema 1 input remains readable; creation uses schema 2. |
| Transaction manifest | schema 3 | Rollback validates supported stored manifests and refuses newer schemas. |
| Operational event | schema 1 | Best-effort JSONL record; logging does not replace the command result. |
| HMAC signature sidecar | schema 2 | New signatures bind the target filename; schema 1 and 2 verify. |
| SARIF | 2.1.0 | Source locations for repository code are supplied explicitly. |

## Stable exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Success |
| 2 | Invalid input, unavailable transaction, or policy error |
| 3 | Baseline drift detected |
| 4 | `audit --fail-on` threshold reached |
| 5 | Files restored but runtime rollback validation failed |
| 6 | Integrity or signature operation failed |
| 7 | Remediation preflight failed |
| 8 | Remediation apply failed |

## Compatibility entry points

The `apply_ssh_fixes` helper remains as a compatibility alias for the generalized remediation engine. New integrations should use the CLI so validation, preflight, transaction logging and rollback behavior stay consistent.

## Release checks

The unit suite contains guards for the published version numbers, exit codes, SARIF format and compatibility entry point. Run the package and disposable integration workflows described in [`TESTING.md`](TESTING.md) when preparing changes that affect those contracts.
