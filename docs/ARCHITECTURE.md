# Architecture

## Security model

Aegis keeps observation, intent, drift and mutation separate:

1. collectors/checks observe current state;
2. role profiles + policy describe intended state;
3. baselines describe previously reviewed state;
4. remediation registry defines reversible supported changes;
5. transaction/runtime validators decide whether the change can commit;
6. reports/event logs retain evidence of what Aegis observed or changed.

## SystemContext

All host filesystem/command access is routed through `SystemContext`. `--root` maps absolute paths into a fake root and disables external commands, allowing read-only checks and file-level remediation behavior to be tested without touching the development host.

A per-run cache prevents repeated expensive inventory collection.

## Checks and tags

Each read-only check returns a `Finding` with stable ID, module, status, severity, current/expected state, rationale, remediation guidance, evidence/references and scoring authority.

Semantic tags are derived from modules (`authentication`, `attack-surface`, `privilege-escalation`, `patching`, etc.) and may be extended per check.

One broken check becomes an unscored `ERROR` and does not abort the audit.

## Role profiles and policy

Built-in `RoleProfile` objects provide inherited defaults and optional control-pack selection. Policy schema v3 adds local overrides and time-bounded exceptions.

An exception is represented as `EXEMPT`; Aegis preserves the original status and never represents governance acceptance as technical compliance.

## Platform adapters

Distribution-specific authority lives under `aegis.platforms`:

- Debian/Ubuntu: dpkg + APT semantics;
- RPM family: rpm + dnf-automatic semantics;
- generic fallback: advisory portable behavior.

Firewall detection is adapter-backed and can inspect UFW, firewalld and nftables.

## Inventory and baseline

Collectors currently retain listening sockets and SUID/SGID executable metadata. Baseline schema v2 includes Aegis version/platform/profile metadata and is backward-readable for schema v1 comparison.

## Remediation

Automatic fixes are registered by stable check ID. A `FixSpec` describes domain, setting, desired value, summary and lockout sensitivity.

Current managed domains are OpenSSH and sysctl. A single invocation may prepare multiple domains before validation/commit.

Managed OpenSSH keys are deduplicated case-insensitively before rendering, preventing contradictory settings inside Aegis's own drop-in.

## Transactions

Manifest schema v3 records:

- transaction ID / timestamp / description;
- file existence and backup payload;
- SHA-256 before/after file state;
- known runtime before/after state.

Rollback performs whole-transaction conflict/integrity preflight before touching files. It refuses to overwrite newer administrator edits unless `--force` is supplied. Runtime actions are unwound in reverse order and validated.

## Evidence integrity

Audit output supports SARIF 2.1.0. Host findings do not inherently identify repository source lines, so GitHub Code Scanning locations are accepted only through an explicit, validated check-ID map.

Report schema v2 and baseline schema v2 can be protected by HMAC-SHA256 sidecars. New signature schema v2 binds the filename into the MAC; schema-v1 signatures remain verifiable for compatibility. HMAC keys must be independently protected; Aegis rejects symlink keys and, on POSIX, group/world-readable key files. Baseline compare verifies and parses one captured byte sequence; an existing signature without a verification key is rejected. Baseline creation is staged, refuses overwrite by default and publishes each file atomically.

## Operational event log

Best-effort JSONL events use schema v1. Event logging is intentionally non-authoritative: failure to append an operational log must not change the result of the underlying security operation. The default event-file path is never followed through a symlink.

## Stable automation interface

The 1.x CLI, automation exit codes and versioned evidence formats follow the compatibility rules in [`V1_COMPATIBILITY.md`](V1_COMPATIBILITY.md). Additive options and fields may be introduced compatibly; breaking changes require a new major CLI contract or a new schema version. The Python package internal modules are not a separate stable API.
