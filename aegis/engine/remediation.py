from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from aegis.checks.ssh import effective_sshd_config
from aegis.context import SystemContext
from aegis.engine.audit import check_by_id
from aegis.engine.runtime import apply_sysctl_values, read_sysctl, validate_sshd
from aegis.engine.transaction import RollbackResult, Transaction, rollback_transaction
from aegis.policy import Policy


SSH_DROPIN = "/etc/ssh/sshd_config.d/00-aegis-hardening.conf"
MAIN_SSHD = "/etc/ssh/sshd_config"
SYSCTL_DROPIN = "/etc/sysctl.d/90-aegis-hardening.conf"


class RemediationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class FixSpec:
    check_id: str
    domain: str
    setting: str
    value: str
    summary: str
    lockout_sensitive: bool = False


@dataclass(slots=True)
class PreflightResult:
    ok: bool
    messages: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


FIX_REGISTRY: dict[str, FixSpec] = {
    "SSH-001": FixSpec("SSH-001", "ssh", "PermitRootLogin", "no", "disable direct root SSH login"),
    "SSH-002": FixSpec(
        "SSH-002", "ssh", "PasswordAuthentication", "no", "disable SSH password authentication", lockout_sensitive=True
    ),
    "SSH-003": FixSpec("SSH-003", "ssh", "MaxAuthTries", "4", "limit SSH authentication attempts"),
    "SSH-004": FixSpec("SSH-004", "ssh", "PermitEmptyPasswords", "no", "disable SSH empty-password authentication"),
    "SSH-005": FixSpec("SSH-005", "ssh", "HostbasedAuthentication", "no", "disable SSH host-based authentication"),
    "SSH-006": FixSpec("SSH-006", "ssh", "IgnoreRhosts", "yes", "ignore legacy rhosts trust"),
    "NET-001": FixSpec("NET-001", "sysctl", "net.ipv4.conf.all.accept_redirects", "0", "disable IPv4 ICMP redirects"),
    "KERN-001": FixSpec("KERN-001", "sysctl", "kernel.randomize_va_space", "2", "enable full ASLR"),
    "KERN-002": FixSpec("KERN-002", "sysctl", "kernel.kptr_restrict", "1", "restrict kernel pointer exposure"),
    "KERN-003": FixSpec("KERN-003", "sysctl", "kernel.dmesg_restrict", "1", "restrict unprivileged dmesg access"),
    "KERN-004": FixSpec("KERN-004", "sysctl", "fs.protected_hardlinks", "1", "enable protected hardlinks"),
    "KERN-005": FixSpec("KERN-005", "sysctl", "fs.protected_symlinks", "1", "enable protected symlinks"),
}


def _normalize_ids(check_ids: list[str]) -> list[str]:
    normalized: list[str] = []
    for raw in check_ids:
        cid = raw.upper()
        if cid not in normalized:
            normalized.append(cid)
    return normalized


def plan_fix(check_ids: list[str]) -> list[str]:
    actions: list[str] = []
    for cid in _normalize_ids(check_ids):
        check = check_by_id(cid)
        if check is None:
            actions.append(f"{cid}: unknown check")
            continue
        spec = FIX_REGISTRY.get(cid)
        if spec is None:
            actions.append(f"{cid}: no automatic remediation")
            continue
        marker = " [LOCKOUT-SENSITIVE]" if spec.lockout_sensitive else ""
        actions.append(f"{cid}: {spec.summary} ({spec.setting}={spec.value}){marker}")
    return actions


def supported_fix_ids() -> list[str]:
    return sorted(FIX_REGISTRY)


def _dropin_supported(ctx: SystemContext) -> bool:
    if not ctx.exists(MAIN_SSHD):
        return False
    text = ctx.read_text(MAIN_SSHD)
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"(?i)^include\s+.*sshd_config\.d/\*\.conf", line):
            return True
    return False


def _existing_key_values(ctx: SystemContext, path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    if not ctx.exists(path):
        return values
    for raw in ctx.read_text(path).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            values[parts[0]] = parts[1]
    return values


def _render_managed_file(header: str, values: dict[str, str]) -> str:
    content = header.rstrip() + "\n"
    for key in sorted(values, key=str.lower):
        content += f"{key} {values[key]}\n"
    return content


def _parse_passwd(ctx: SystemContext) -> dict[str, tuple[int, int, str]]:
    users: dict[str, tuple[int, int, str]] = {}
    if not ctx.exists("/etc/passwd"):
        return users
    for raw in ctx.read_text("/etc/passwd").splitlines():
        parts = raw.split(":")
        if len(parts) < 7:
            continue
        try:
            uid, gid = int(parts[2]), int(parts[3])
        except ValueError:
            continue
        users[parts[0]] = (uid, gid, parts[5])
    return users


def _admin_group_members(ctx: SystemContext) -> set[str]:
    members: set[str] = set()
    if not ctx.exists("/etc/group"):
        return members
    for raw in ctx.read_text("/etc/group").splitlines():
        parts = raw.split(":")
        if len(parts) != 4 or parts[0] not in {"sudo", "wheel"}:
            continue
        members.update(user for user in parts[3].split(",") if user)
    return members


def _authorized_keys_candidates(home: str, configured: str | None, username: str) -> list[str]:
    patterns = (configured or ".ssh/authorized_keys .ssh/authorized_keys2").split()
    paths: list[str] = []
    for pattern in patterns:
        expanded = pattern.replace("%u", username).replace("%%", "%")
        if expanded.startswith("/"):
            paths.append(expanded)
        else:
            paths.append(str(Path(home) / expanded))
    return paths


def _usable_authorized_keys(ctx: SystemContext, path: str, uid: int) -> tuple[bool, str]:
    target = ctx.path(path)
    if not target.is_file():
        return False, f"{path}: missing"
    try:
        stat = target.stat()
        parent_stat = target.parent.stat()
        text = target.read_text(encoding="utf-8")
    except OSError as exc:
        return False, f"{path}: {exc}"
    if stat.st_uid not in {0, uid}:
        return False, f"{path}: unexpected owner uid {stat.st_uid}"
    if stat.st_mode & 0o022:
        return False, f"{path}: group/world writable"
    if parent_stat.st_mode & 0o022:
        return False, f"{target.parent}: group/world writable"
    keys = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not keys:
        return False, f"{path}: no active keys"
    return True, f"{path}: {len(keys)} active key line(s)"


def preflight_ssh_password_disable(ctx: SystemContext) -> PreflightResult:
    messages: list[str] = []
    warnings = [
        "Local preflight cannot prove that a remote key login succeeds through your network path, bastion, IAM layer, or Match rules. Keep a second tested administrative session open before applying."
    ]
    if not ctx.is_real_system:
        return PreflightResult(False, ["SSH lockout-sensitive preflight requires the live target host"], warnings)

    cfg, authoritative, source = effective_sshd_config(ctx)
    if not authoritative:
        return PreflightResult(False, [f"effective SSH configuration is not authoritative ({source})"], warnings)
    if cfg.get("pubkeyauthentication", "yes").lower() != "yes":
        return PreflightResult(False, ["PubkeyAuthentication is not enabled in the effective SSH configuration"], warnings)
    auth_methods = cfg.get("authenticationmethods", "any").lower()
    if auth_methods != "any" and ("password" in auth_methods or "keyboard-interactive" in auth_methods):
        return PreflightResult(
            False,
            [f"AuthenticationMethods={auth_methods} depends on an interactive/password method"],
            warnings,
        )

    policy = Policy.load(ctx)
    if policy.explicit and not policy.valid:
        return PreflightResult(False, ["host policy is invalid: " + "; ".join(policy.validation_errors)], warnings)
    if policy.expected_password_authentication == "enabled":
        return PreflightResult(False, ["host policy explicitly expects SSH password authentication to remain enabled"], warnings)

    users = _parse_passwd(ctx)
    candidates = set(policy.admin_users) if policy.admin_users else _admin_group_members(ctx)
    candidates.discard("root")
    if not candidates:
        return PreflightResult(
            False,
            ["no non-root administrative users declared in policy or found in sudo/wheel groups"],
            warnings,
        )

    authorized_keys = cfg.get("authorizedkeysfile")
    usable_users: list[str] = []
    for username in sorted(candidates):
        entry = users.get(username)
        if entry is None:
            messages.append(f"{username}: not present in /etc/passwd")
            continue
        uid, _gid, home = entry
        usable = False
        details: list[str] = []
        for path in _authorized_keys_candidates(home, authorized_keys, username):
            ok, detail = _usable_authorized_keys(ctx, path, uid)
            details.append(detail)
            usable = usable or ok
        messages.append(f"{username}: " + "; ".join(details))
        if usable:
            usable_users.append(username)

    if not usable_users:
        messages.append("no administrative account passed local authorized_keys checks")
        return PreflightResult(False, messages, warnings)
    messages.append("local key preflight passed for: " + ", ".join(usable_users))
    return PreflightResult(True, messages, warnings)


def preflight_fixes(
    ctx: SystemContext,
    check_ids: list[str],
    *,
    acknowledge_lockout_sensitive: bool = False,
    require_lockout_ack: bool = False,
) -> PreflightResult:
    wanted = _normalize_ids(check_ids)
    messages: list[str] = []
    warnings: list[str] = []

    unknown = [cid for cid in wanted if check_by_id(cid) is None]
    if unknown:
        return PreflightResult(False, ["unknown checks: " + ", ".join(unknown)])
    unsupported = [cid for cid in wanted if cid not in FIX_REGISTRY]
    if unsupported:
        return PreflightResult(False, ["no automatic remediation for: " + ", ".join(unsupported)])
    if not wanted:
        return PreflightResult(False, ["no checks selected"])
    if ctx.is_real_system and os.geteuid() != 0:
        return PreflightResult(False, ["root privileges are required to apply system changes"])

    domains = {FIX_REGISTRY[cid].domain for cid in wanted}
    if "ssh" in domains:
        if not _dropin_supported(ctx):
            return PreflightResult(False, ["/etc/ssh/sshd_config does not actively include sshd_config.d/*.conf"])
        if ctx.is_real_system and not ctx.which("sshd"):
            return PreflightResult(False, ["sshd executable not found"])
        messages.append("OpenSSH managed drop-in is available")

    if "sysctl" in domains:
        for cid in wanted:
            spec = FIX_REGISTRY[cid]
            if spec.domain != "sysctl":
                continue
            if read_sysctl(ctx, spec.setting) is None:
                return PreflightResult(False, [f"{spec.setting} is unavailable on this host"])
        if ctx.is_real_system and not ctx.which("sysctl"):
            return PreflightResult(False, ["sysctl executable not found"])
        messages.append("all selected sysctl keys are available")

    if any(FIX_REGISTRY[cid].lockout_sensitive for cid in wanted):
        ssh_preflight = preflight_ssh_password_disable(ctx)
        messages.extend(ssh_preflight.messages)
        warnings.extend(ssh_preflight.warnings)
        if not ssh_preflight.ok:
            return PreflightResult(False, messages, warnings)
        if require_lockout_ack and not acknowledge_lockout_sensitive:
            messages.append("explicit --acknowledge-lockout-risk is required for SSH-002")
            return PreflightResult(False, messages, warnings)

    return PreflightResult(True, messages, warnings)


def _rollback_failed_apply(ctx: SystemContext, tx: Transaction, reason: str) -> RemediationError:
    tx.commit_manifest()
    result: RollbackResult = rollback_transaction(ctx, tx.transaction_id, force=True)
    runtime_failures = [message for item in result.runtime_results if not item.ok for message in item.messages]
    suffix = ""
    if runtime_failures:
        suffix = "; rollback runtime validation also failed: " + "; ".join(runtime_failures)
    return RemediationError(reason + "; transaction rolled back" + suffix)


def _prepare_ssh(ctx: SystemContext, tx: Transaction, specs: list[FixSpec]) -> tuple[dict[str, str], dict[str, str]]:
    existing = _existing_key_values(ctx, SSH_DROPIN)
    for spec in specs:
        for key in list(existing):
            if key.lower() == spec.setting.lower():
                del existing[key]
        existing[spec.setting] = spec.value
    content = _render_managed_file("# Managed by Aegis. Manual edits may be overwritten.", existing)

    effective_before, authoritative, _source = effective_sshd_config(ctx)
    before = {spec.setting.lower(): effective_before.get(spec.setting.lower(), "unknown").lower() for spec in specs}
    after = {spec.setting.lower(): spec.value.lower() for spec in specs}

    tx.backup(SSH_DROPIN)
    tx.atomic_write(SSH_DROPIN, content, 0o644)
    tx.add_runtime_action("sshd", before=before, after=after)
    if ctx.is_real_system and not authoritative:
        raise _rollback_failed_apply(ctx, tx, "could not obtain authoritative pre-change SSH configuration")
    return before, after


def _prepare_sysctl(ctx: SystemContext, tx: Transaction, specs: list[FixSpec]) -> tuple[dict[str, str], dict[str, str]]:
    existing = _existing_key_values(ctx, SYSCTL_DROPIN)
    before: dict[str, str] = {}
    after: dict[str, str] = {}
    for spec in specs:
        current = read_sysctl(ctx, spec.setting)
        if current is None:
            raise _rollback_failed_apply(ctx, tx, f"{spec.setting} became unavailable during remediation")
        before[spec.setting] = current
        after[spec.setting] = spec.value
        # sysctl syntax uses '=' and is clearer than whitespace for managed files.
        existing[spec.setting] = f"= {spec.value}"

    content = "# Managed by Aegis. Manual edits may be overwritten.\n"
    for key in sorted(existing):
        raw_value = existing[key]
        if raw_value.lstrip().startswith("="):
            content += f"{key} {raw_value}\n"
        else:
            content += f"{key} = {raw_value}\n"

    tx.backup(SYSCTL_DROPIN)
    tx.atomic_write(SYSCTL_DROPIN, content, 0o644)
    tx.add_runtime_action("sysctl", before=before, after=after)
    return before, after


def apply_fixes(
    ctx: SystemContext,
    check_ids: list[str],
    *,
    dry_run: bool = False,
    acknowledge_lockout_sensitive: bool = False,
) -> str | None:
    wanted = _normalize_ids(check_ids)
    preflight = preflight_fixes(
        ctx,
        wanted,
        acknowledge_lockout_sensitive=acknowledge_lockout_sensitive,
        require_lockout_ack=True,
    )
    if not preflight.ok:
        raise RemediationError("preflight failed: " + "; ".join(preflight.messages))
    if dry_run:
        return None

    specs = [FIX_REGISTRY[cid] for cid in wanted]
    tx = Transaction(ctx, description="Aegis remediation: " + ", ".join(wanted))
    by_domain: dict[str, list[FixSpec]] = {}
    for spec in specs:
        by_domain.setdefault(spec.domain, []).append(spec)

    ssh_after: dict[str, str] | None = None
    sysctl_after: dict[str, str] | None = None
    try:
        if "ssh" in by_domain:
            _before, ssh_after = _prepare_ssh(ctx, tx, by_domain["ssh"])
        if "sysctl" in by_domain:
            _before, sysctl_after = _prepare_sysctl(ctx, tx, by_domain["sysctl"])

        if ssh_after is not None:
            result = validate_sshd(ctx, ssh_after, reload_service=True)
            if not result.ok:
                raise _rollback_failed_apply(ctx, tx, "SSH validation/reload failed: " + "; ".join(result.messages))

        if sysctl_after is not None:
            result = apply_sysctl_values(ctx, sysctl_after)
            if not result.ok:
                raise _rollback_failed_apply(ctx, tx, "sysctl apply/validation failed: " + "; ".join(result.messages))

        tx.commit_manifest()
        return tx.transaction_id
    except RemediationError:
        raise
    except Exception as exc:
        raise _rollback_failed_apply(ctx, tx, f"unexpected remediation failure: {type(exc).__name__}: {exc}") from exc


# Stable compatibility alias for callers of the pre-v1 SSH remediation API.
def apply_ssh_fixes(ctx: SystemContext, check_ids: list[str], *, dry_run: bool = False) -> str | None:
    return apply_fixes(ctx, check_ids, dry_run=dry_run)
