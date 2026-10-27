# Aegis v1.1.0

Aegis is a defensive Linux security auditing and safe-hardening framework written in Python.

> **Do not change a security-sensitive setting unless Aegis can inspect the current state, preserve it, validate the replacement, and recover from failure.**

`v1.1.0` adds full-audit snapshots and change classification to Aegis’s stable 1.x command-line and evidence formats. It includes 37 checks, 12 managed fixes, role profiles, HMAC-signed evidence, baseline drift detection and conflict-aware rollback. Review snapshots before using their differences in automation.

## What Aegis does

Aegis separates five different security questions:

1. **Observation** — what is the host actually doing?
2. **Intent** — what should this host be doing for its role?
3. **Drift** — what changed since a reviewed baseline?
4. **Remediation** — can a supported correction be applied safely and atomically?
5. **Evidence** — can the resulting report/baseline be retained and verified later?

Current coverage contains **37 checks**, **12 managed fixes**, six built-in role profiles, JSON/HTML/SARIF reports, HMAC integrity metadata, attack-surface inventory, baseline drift, and conflict-aware rollback.

## Install for development

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest
```

System-wide lab install:

```bash
sudo ./scripts/install.sh
```

The installer creates `/etc/aegis/policy.example.json`, **not** an active policy. Copy/edit it as `/etc/aegis/policy.json` only after reviewing the host role and intended exposure.

Uninstall while preserving policy/state/logs:

```bash
sudo ./scripts/uninstall.sh
```

Explicit purge:

```bash
sudo ./scripts/uninstall.sh --purge
```

## Fast start

Inspect prerequisites:

```bash
aegis doctor
```

List role profiles:

```bash
aegis profiles
```

Run the full audit using the policy profile (or `general` when no policy exists):

```bash
sudo aegis audit
```

Run a bastion-host view:

```bash
sudo aegis audit --profile bastion
```

Select semantic controls:

```bash
sudo aegis audit --tag authentication
sudo aegis audit --tag attack-surface
```

Generate reports:

```bash
sudo aegis audit --json report.json --html report.html --sarif results.sarif
```

SARIF 2.1.0 results include stable Aegis check IDs and evidence. For GitHub Code Scanning, provide a reviewed mapping to real repository files and lines:

```bash
sudo aegis audit --sarif results.sarif --sarif-location-map sarif-locations.json
```

Example `sarif-locations.json`:

```json
{
  "SSH-001": {"uri": "infra/ssh/sshd_config", "line": 12},
  "KERN-001": {"uri": "infra/sysctl/99-hardening.conf", "line": 4}
}
```

Every active finding must have a mapping when this option is used. Paths must be repository-relative and point to committed files in the repository analyzed by GitHub. Without a location map, Aegis emits location-free SARIF for consumers that support host-level findings; GitHub Code Scanning requires at least one source location for an alert to display. Aegis never invents a source file or line. See [GitHub SARIF requirements](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support#source-file-locations).

Fail CI when authoritative HIGH/CRITICAL checks fail:

```bash
aegis audit --fail-on high
```

## Role profiles

Built-ins:

- `general`
- `web-server`
- `database`
- `bastion`
- `container-host`
- `minimal`

Profiles provide inherited role intent. Local policy can override public-port expectations and control selection. For example, `web-server` expects `22/80/443` by default, while `bastion` expects only `22`.

A `database` profile does **not** automatically approve public PostgreSQL/MySQL exposure. Public database ports must be an explicit local policy decision.

## Policy schema v3

Example:

```json
{
  "schema_version": 3,
  "profile": "web-server",
  "network": {
    "allowed_public_ports": [22, 80, 443]
  },
  "privilege": {
    "allowed_suid_sgid": []
  },
  "ssh": {
    "admin_users": ["admin"],
    "expected_password_authentication": "disabled"
  },
  "controls": {
    "include": [],
    "exclude": []
  },
  "exceptions": [
    {
      "check_id": "SVC-001",
      "reason": "Temporary compensating control during migration",
      "expires_at": "2026-12-31",
      "ticket": "SEC-1234"
    }
  ]
}
```

Validate:

```bash
aegis policy validate /etc/aegis/policy.json
```

Migrate older policy formats:

```bash
aegis policy migrate old-policy.json policy-v3.json
```

### Exceptions are not PASS

An active exception becomes `EXEMPT`, retains the original status, is removed from scoring, and records rationale/expiry/ticket in machine-readable reports. Expired exceptions are ignored and surfaced as evidence.

## Attack-surface inventory

Listening sockets:

```bash
sudo aegis inventory sockets
```

SUID/SGID executables:

```bash
sudo aegis inventory suid
```

Aegis distinguishes inventory from vulnerability claims. A listener or SUID binary is not automatically unsafe simply because it exists.

## Baseline and drift

Create only after manually reviewing the host:

```bash
sudo aegis baseline create baseline.json
```

Compare later:

```bash
sudo aegis baseline compare baseline.json
```

Aegis refuses to overwrite an existing baseline or signature unless `--force` is supplied. A baseline with a `.sig` sidecar is never compared silently: pass `--verify-key` or the comparison fails. Use `--require-signature` to reject unsigned baselines as well.

Drift covers listener identities and SUID/SGID file metadata/provenance. Baseline JSON is schema-validated before comparison, and signed comparisons verify the exact bytes that are then parsed.

## Full-audit snapshots and diff

Capture all audit findings, or a repeatable module/tag scope, without changing host settings:

```bash
sudo aegis snapshot create before.json --host-id web-01 --sign-key /secure/aegis-integrity.key
# Later, after the next audit window:
sudo aegis snapshot create after.json --host-id web-01 --sign-key /secure/aegis-integrity.key

sudo aegis snapshot diff before.json after.json \
  --verify-key /secure/aegis-integrity.key --require-signature
```

The diff groups added and removed checks, resolved findings, regressions and other changes. Use `--json` for machine-readable output; code 9 means findings changed. Comparisons require matching module/tag scopes and reject different host IDs. `--host-id` is optional; without it, Aegis warns that the same host could not be confirmed. Creation refuses to overwrite a snapshot or signature unless `--force` is supplied.

Snapshots contain audit evidence and may reveal host details. Store and share them with the same care as JSON audit reports.

## HMAC integrity for evidence

Generate a local secret key:

```bash
aegis integrity keygen /secure/aegis-integrity.key
```

On POSIX hosts, Aegis requires the key to be mode `0600` or stricter and refuses symlink keys.

Signed reports:

```bash
sudo aegis audit \
  --json report.json \
  --html report.html \
  --sarif results.sarif \
  --sign-key /secure/aegis-integrity.key
```

Verify later:

```bash
aegis integrity verify report.json --key /secure/aegis-integrity.key
```

Signed baseline:

```bash
sudo aegis baseline create baseline.json --sign-key /secure/aegis-integrity.key
sudo aegis baseline compare baseline.json --verify-key /secure/aegis-integrity.key
```

New signature schema v2 binds the target filename into the MAC; schema-v1 signatures remain verifiable for existing evidence. The `.sig` file is useful only while the HMAC key remains independently protected. HMAC is a shared-secret integrity mechanism: anyone holding the key can create a valid signature, so distribute verification keys only to trusted operators.

## Safe remediation

List supported fixes:

```bash
aegis list-fixes
```

Current managed controls:

```text
SSH-001  PermitRootLogin=no
SSH-002  PasswordAuthentication=no        [lockout-sensitive]
SSH-003  MaxAuthTries=4
SSH-004  PermitEmptyPasswords=no
SSH-005  HostbasedAuthentication=no
SSH-006  IgnoreRhosts=yes
NET-001  net.ipv4.conf.all.accept_redirects=0
KERN-001 kernel.randomize_va_space=2
KERN-002 kernel.kptr_restrict=1
KERN-003 kernel.dmesg_restrict=1
KERN-004 fs.protected_hardlinks=1
KERN-005 fs.protected_symlinks=1
```

Plan and preflight:

```bash
aegis plan SSH-001 KERN-001 KERN-003
sudo aegis preflight SSH-001 KERN-001 KERN-003
```

Apply as one transaction:

```bash
sudo aegis fix SSH-001 KERN-001 KERN-003
```

Aegis manages dedicated drop-ins instead of blind primary-file rewrites:

```text
/etc/ssh/sshd_config.d/00-aegis-hardening.conf
/etc/sysctl.d/90-aegis-hardening.conf
```

For `SSH-002`, local key/admin preflight plus explicit acknowledgement is required:

```bash
sudo aegis fix SSH-002 --acknowledge-lockout-risk
```

Local preflight still cannot prove that the operator's real remote path, bastion, IAM layer, firewall and client key will work. Keep a tested second administrative session open.

## Transactions and rollback

```bash
aegis transactions
sudo aegis rollback <transaction-id>
```

Transaction manifest schema v3 records file existence, backup payloads, SHA-256 before/after state, and known runtime before/after state. Rollback refuses to overwrite administrator changes made after Aegis unless `--force` is explicitly supplied.

Known runtime state (OpenSSH/sysctl) is replayed and validated after file restoration.

## Structured event log

Operational events are written best-effort as JSONL to:

```text
/var/log/aegis/events.jsonl
```

Override with `AEGIS_EVENT_LOG`. The logger refuses to follow a symlink at the configured event-file path.

## Stable exit codes

```text
0  success
2  invalid input / unavailable transaction / policy error
3  baseline drift detected
4  audit --fail-on threshold reached
5  files restored but runtime rollback validation failed
6  integrity/signature operation failed
7  remediation preflight failed
8  remediation apply failed
```

## Distribution adapters

Current adapter families:

- Debian/Ubuntu: `dpkg-query`, APT/unattended-upgrades semantics;
- Fedora/RHEL/Rocky/Alma family: `rpm`, dnf-automatic semantics;
- Generic Linux: portable/advisory fallback where authoritative distro behavior is unavailable.

Firewall discovery understands UFW, firewalld and restrictive nftables input policy.

## Compatibility and verification

The 1.x compatibility contract is documented in [`docs/V1_COMPATIBILITY.md`](docs/V1_COMPATIBILITY.md). Unit, package and integration commands are listed in [`docs/TESTING.md`](docs/TESTING.md). The container matrix and VM procedures use disposable systems so service reloads, persistence and rollback can be exercised safely.

## Project layout

```text
aegis/
├── checks/          read-only security controls
├── engine/          audit, scoring, transactions and remediation
├── inventory/       sockets and SUID/SGID collectors
├── platforms/       distro-specific authority adapters
├── reporting/       console, JSON, HTML and SARIF
├── baseline.py
├── policy.py
├── profiles.py
├── integrity.py
├── fileio.py
├── eventlog.py
├── doctor.py
└── cli.py

tests/
integration/
completions/
scripts/
docs/
.github/workflows/
```

Before adding an automatic fix, read `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md` and `docs/REMEDIATION.md`.
