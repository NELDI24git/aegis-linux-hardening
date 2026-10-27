from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from aegis.context import SystemContext
from aegis.profiles import PROFILES, get_profile


POLICY_SCHEMA_VERSION = 3
DEFAULT_POLICY_PATH = "/etc/aegis/policy.json"

DEFAULT_SENSITIVE_PORTS = {
    21: "FTP",
    23: "Telnet",
    2375: "Docker API (unencrypted)",
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


class PolicyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PolicyException:
    check_id: str
    reason: str
    expires_at: str
    ticket: str | None = None

    def active(self, *, today: date | None = None) -> bool:
        today = today or datetime.now(timezone.utc).date()
        try:
            return date.fromisoformat(self.expires_at) >= today
        except ValueError:
            return False


def _parse_port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _validate_string_list(value: Any, path: str, *, absolute: bool = False) -> list[str]:
    errors: list[str] = []
    if value is None:
        return errors
    if not isinstance(value, list):
        return [f"{path} must be an array"]
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{path}[{index}] must be a non-empty string")
        elif absolute and not item.startswith("/"):
            errors.append(f"{path}[{index}] must be an absolute path")
    return errors


def validate_policy_dict(raw: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(raw, dict):
        return ["policy document must be a JSON object"]
    if raw.get("schema_version") != POLICY_SCHEMA_VERSION:
        errors.append(f"schema_version must be {POLICY_SCHEMA_VERSION}")

    profile = raw.get("profile", raw.get("host_role", "general"))
    if not isinstance(profile, str) or profile not in PROFILES:
        errors.append(f"profile must be one of: {', '.join(sorted(PROFILES))}")

    network = raw.get("network", {})
    if not isinstance(network, dict):
        errors.append("network must be an object")
    else:
        ports = network.get("allowed_public_ports")
        if ports is not None:
            if not isinstance(ports, list):
                errors.append("network.allowed_public_ports must be an array")
            else:
                seen: set[int] = set()
                for index, value in enumerate(ports):
                    port = _parse_port(value)
                    if port is None:
                        errors.append(f"network.allowed_public_ports[{index}] must be an integer from 1 to 65535")
                    elif port in seen:
                        errors.append(f"network.allowed_public_ports contains duplicate port {port}")
                    else:
                        seen.add(port)
        sensitive = network.get("sensitive_ports")
        if sensitive is not None:
            if not isinstance(sensitive, dict):
                errors.append("network.sensitive_ports must be an object mapping ports to labels")
            else:
                for key, label in sensitive.items():
                    if _parse_port(key) is None:
                        errors.append(f"network.sensitive_ports key {key!r} is not a valid port")
                    if not isinstance(label, str) or not label.strip():
                        errors.append(f"network.sensitive_ports[{key!r}] must be a non-empty string")

    privilege = raw.get("privilege", {})
    if not isinstance(privilege, dict):
        errors.append("privilege must be an object")
    else:
        errors.extend(_validate_string_list(privilege.get("allowed_suid_sgid"), "privilege.allowed_suid_sgid", absolute=True))

    ssh = raw.get("ssh", {})
    if not isinstance(ssh, dict):
        errors.append("ssh must be an object")
    else:
        errors.extend(_validate_string_list(ssh.get("admin_users"), "ssh.admin_users"))
        expected = ssh.get("expected_password_authentication", "disabled")
        if expected not in {"disabled", "enabled", "unspecified"}:
            errors.append("ssh.expected_password_authentication must be disabled, enabled, or unspecified")

    controls = raw.get("controls", {})
    if not isinstance(controls, dict):
        errors.append("controls must be an object")
    else:
        errors.extend(_validate_string_list(controls.get("include"), "controls.include"))
        errors.extend(_validate_string_list(controls.get("exclude"), "controls.exclude"))

    exceptions = raw.get("exceptions", [])
    if not isinstance(exceptions, list):
        errors.append("exceptions must be an array")
    else:
        seen_ids: set[str] = set()
        for index, item in enumerate(exceptions):
            base = f"exceptions[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{base} must be an object")
                continue
            cid = item.get("check_id")
            if not isinstance(cid, str) or not cid.strip():
                errors.append(f"{base}.check_id must be a non-empty string")
            elif cid.upper() in seen_ids:
                errors.append(f"duplicate exception for {cid.upper()}")
            else:
                seen_ids.add(cid.upper())
            reason = item.get("reason")
            if not isinstance(reason, str) or len(reason.strip()) < 8:
                errors.append(f"{base}.reason must contain a meaningful rationale")
            expires = item.get("expires_at")
            if not isinstance(expires, str):
                errors.append(f"{base}.expires_at must be YYYY-MM-DD")
            else:
                try:
                    date.fromisoformat(expires)
                except ValueError:
                    errors.append(f"{base}.expires_at must be YYYY-MM-DD")
            ticket = item.get("ticket")
            if ticket is not None and (not isinstance(ticket, str) or not ticket.strip()):
                errors.append(f"{base}.ticket must be a non-empty string when provided")
    return errors


def migrate_policy_dict(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PolicyError("policy document must be a JSON object")
    schema = raw.get("schema_version")
    if schema == POLICY_SCHEMA_VERSION:
        migrated = raw
    elif schema == 2:
        migrated = {
            "schema_version": POLICY_SCHEMA_VERSION,
            "profile": raw.get("host_role", "general") if raw.get("host_role") in PROFILES else "general",
            "network": raw.get("network", {}),
            "privilege": raw.get("privilege", {}),
            "ssh": raw.get("ssh", {}),
            "controls": {"include": [], "exclude": []},
            "exceptions": [],
        }
    elif schema is None:
        migrated = {
            "schema_version": POLICY_SCHEMA_VERSION,
            "profile": raw.get("host_role", "general") if raw.get("host_role") in PROFILES else "general",
            "network": {"allowed_public_ports": raw.get("allowed_public_ports", [22])},
            "privilege": {"allowed_suid_sgid": raw.get("allowed_privileged_files", [])},
            "ssh": {"admin_users": raw.get("admin_users", []), "expected_password_authentication": "disabled"},
            "controls": {"include": [], "exclude": []},
            "exceptions": [],
        }
    else:
        raise PolicyError(f"unsupported policy schema_version {schema!r}")
    errors = validate_policy_dict(migrated)
    if errors:
        raise PolicyError("invalid policy: " + "; ".join(errors))
    return migrated


@dataclass(slots=True)
class Policy:
    schema_version: int = POLICY_SCHEMA_VERSION
    profile: str = "general"
    allowed_public_ports: set[int] = field(default_factory=lambda: set(get_profile("general").default_public_ports))
    allowed_public_ports_explicit: bool = False
    sensitive_ports: dict[int, str] = field(default_factory=lambda: dict(DEFAULT_SENSITIVE_PORTS))
    allowed_privileged_files: set[str] = field(default_factory=set)
    admin_users: set[str] = field(default_factory=set)
    expected_password_authentication: str = "disabled"
    include_controls: set[str] = field(default_factory=set)
    exclude_controls: set[str] = field(default_factory=set)
    exceptions: dict[str, PolicyException] = field(default_factory=dict)
    explicit: bool = False
    validation_errors: list[str] = field(default_factory=list)

    @property
    def host_role(self) -> str:  # compatibility with v2 callers
        return self.profile

    @property
    def valid(self) -> bool:
        return not self.validation_errors

    @classmethod
    def from_dict(cls, raw: Any, *, explicit: bool = True, allow_legacy: bool = True) -> "Policy":
        policy = cls(explicit=explicit)
        if allow_legacy and isinstance(raw, dict) and raw.get("schema_version") != POLICY_SCHEMA_VERSION:
            try:
                raw = migrate_policy_dict(raw)
            except PolicyError as exc:
                policy.validation_errors = [str(exc)]
                return policy
        errors = validate_policy_dict(raw)
        if errors:
            policy.validation_errors = errors
            return policy
        assert isinstance(raw, dict)
        policy.profile = raw.get("profile", "general")
        profile = get_profile(policy.profile)
        network = raw.get("network", {})
        privilege = raw.get("privilege", {})
        ssh = raw.get("ssh", {})
        controls = raw.get("controls", {})
        ports = network.get("allowed_public_ports")
        policy.allowed_public_ports = set(profile.default_public_ports if ports is None else map(int, ports))
        policy.allowed_public_ports_explicit = ports is not None
        policy.allowed_privileged_files = set(privilege.get("allowed_suid_sgid", []))
        policy.admin_users = set(ssh.get("admin_users", []))
        policy.expected_password_authentication = ssh.get("expected_password_authentication", "disabled")
        policy.include_controls = {str(x).upper() for x in controls.get("include", [])}
        policy.exclude_controls = {str(x).upper() for x in controls.get("exclude", [])}
        for item in raw.get("exceptions", []):
            exc = PolicyException(str(item["check_id"]).upper(), item["reason"].strip(), item["expires_at"], item.get("ticket"))
            policy.exceptions[exc.check_id] = exc
        sensitive = network.get("sensitive_ports")
        if isinstance(sensitive, dict):
            policy.sensitive_ports = dict(DEFAULT_SENSITIVE_PORTS)
            for key, label in sensitive.items():
                parsed = _parse_port(key)
                if parsed is not None:
                    policy.sensitive_ports[parsed] = str(label)
        return policy

    @classmethod
    def load(cls, ctx: SystemContext, path: str = DEFAULT_POLICY_PATH) -> "Policy":
        cached = ctx.cache.get("aegis.policy")
        if isinstance(cached, cls):
            return cached
        if not ctx.exists(path):
            policy = cls()
            ctx.cache["aegis.policy"] = policy
            return policy
        try:
            raw = json.loads(ctx.read_text(path))
        except (json.JSONDecodeError, OSError) as exc:
            policy = cls(explicit=True)
            policy.validation_errors = [f"cannot parse {path}: {exc}"]
            return policy
        policy = cls.from_dict(raw, explicit=True, allow_legacy=True)
        ctx.cache["aegis.policy"] = policy
        return policy

    def control_enabled(self, check_id: str, module: str) -> bool:
        cid = check_id.upper()
        if cid in self.exclude_controls:
            return False
        if cid in self.include_controls:
            return True
        return get_profile(self.profile).check_enabled(check_id=cid, module=module)

    def exception_for(self, check_id: str) -> PolicyException | None:
        return self.exceptions.get(check_id.upper())


def load_policy_path(path: str | Path, *, allow_legacy: bool = True) -> Policy:
    target = Path(path)
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        policy = Policy(explicit=True)
        policy.validation_errors = [f"cannot parse {target}: {exc}"]
        return policy
    return Policy.from_dict(raw, explicit=True, allow_legacy=allow_legacy)


def example_policy() -> dict[str, Any]:
    # Intentionally neutral: printing an example must not silently choose a host role
    # or create a real compliance exception if an operator uses it as a template.
    return {
        "schema_version": POLICY_SCHEMA_VERSION,
        "profile": "general",
        "network": {},
        "privilege": {"allowed_suid_sgid": []},
        "ssh": {"admin_users": [], "expected_password_authentication": "disabled"},
        "controls": {"include": [], "exclude": []},
        "exceptions": [],
    }
