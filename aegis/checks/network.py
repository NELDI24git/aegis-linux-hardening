from __future__ import annotations

from aegis.checks.base import Check
from aegis.context import SystemContext
from aegis.inventory.sockets import collect_listening_sockets
from aegis.models import Finding, Severity, Status
from aegis.policy import Policy
from aegis.platforms import get_platform_adapter


class IPv4RedirectsCheck(Check):
    check_id = "NET-001"
    module = "network"
    title = "IPv4 ICMP redirects not accepted"

    def run(self, ctx: SystemContext) -> Finding:
        path = "/proc/sys/net/ipv4/conf/all/accept_redirects"
        if not ctx.exists(path):
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.LOW,
                "sysctl unavailable", "0",
                "ICMP redirect acceptance is normally unnecessary on hardened servers.",
                "Review this setting when running on a standard Linux host.", False,
                scored=False,
            )
        value = ctx.read_text(path).strip()
        return Finding(
            self.check_id,
            self.title,
            self.module,
            Status.PASS if value == "0" else Status.FAIL,
            Severity.MEDIUM,
            f"net.ipv4.conf.all.accept_redirects={value}",
            "0",
            "Accepting redirects can allow network-path manipulation on systems that do not require this behavior.",
            "Set net.ipv4.conf.all.accept_redirects=0 after confirming redirects are not required.",
            auto_fix=True,
            references=["Linux kernel ip-sysctl documentation"],
        )


class FirewallActiveCheck(Check):
    check_id = "NET-002"
    module = "network"
    title = "Host firewall detected and active"

    def run(self, ctx: SystemContext) -> Finding:
        state = get_platform_adapter(ctx).firewall_state(ctx)
        if not state.authoritative or state.active is None:
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.HIGH,
                "; ".join(state.evidence) or "firewall state unavailable", "active host firewall",
                "A host firewall limits unintended network exposure and provides defense in depth.",
                "Run as root on the target host to inspect the effective UFW, firewalld, or nftables state.",
                auto_fix=False, evidence=state.evidence, scored=False,
            )
        if state.active:
            status = Status.PASS
            current = "active: " + ", ".join(state.backends or ["host firewall"])
        elif state.backends:
            status = Status.FAIL
            current = "detected but no active restrictive policy: " + ", ".join(state.backends)
        else:
            status = Status.FAIL
            current = "no supported host firewall detected"
        return Finding(
            self.check_id, self.title, self.module, status, Severity.HIGH, current,
            "an active UFW, firewalld, or restrictive nftables input policy",
            "A host firewall reduces the blast radius of accidentally exposed services.",
            "Define an explicit inbound policy for the host. Aegis does not auto-enable a firewall without an allowlist because doing so can cut off remote administration.",
            auto_fix=False, evidence=state.evidence,
        )


class SensitiveListenerExposureCheck(Check):
    check_id = "NET-003"
    module = "network"
    title = "Sensitive services are not broadly exposed"

    def run(self, ctx: SystemContext) -> Finding:
        sockets, source = collect_listening_sockets(ctx)
        if not sockets:
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.MEDIUM,
                source, "no sensitive service bound to wildcard interfaces",
                "Database, cache, remote-management, and plaintext services are frequent targets when exposed to untrusted networks.",
                "Run on the target host and review the listener inventory.",
                scored=False,
            )

        policy = Policy.load(ctx)
        if policy.explicit and not policy.valid:
            return Finding(
                self.check_id, self.title, self.module, Status.ERROR, Severity.MEDIUM,
                "invalid /etc/aegis/policy.json", "valid host policy or built-in defaults",
                "A malformed host policy can make exposure classification unreliable.",
                "Run `aegis policy validate /etc/aegis/policy.json` and fix the reported schema errors.",
                auto_fix=False, evidence=policy.validation_errors, scored=False,
            )
        risky = [s for s in sockets if s.wildcard and s.port in policy.sensitive_ports]
        evidence = [f"{s.display()} ({policy.sensitive_ports[s.port]})" for s in risky]
        return Finding(
            self.check_id,
            self.title,
            self.module,
            Status.WARN if risky else Status.PASS,
            Severity.HIGH if risky else Severity.MEDIUM,
            f"{len(risky)} broadly exposed sensitive listener(s) ({source})" if risky else f"none detected ({source})",
            "no sensitive service bound to 0.0.0.0/:: unless explicitly required",
            "Broad exposure of databases, caches, plaintext protocols, or management APIs increases remote attack surface.",
            "Confirm each listener is intentional, restrict its bind address and firewall scope, or explicitly document it in the host policy.",
            auto_fix=False,
            evidence=evidence,
        )


class PublicListenerPolicyCheck(Check):
    check_id = "NET-004"
    module = "network"
    title = "Public listeners match the configured allowlist"

    def run(self, ctx: SystemContext) -> Finding:
        sockets, source = collect_listening_sockets(ctx)
        if not sockets:
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.LOW,
                source, "public listeners match policy",
                "An explicit allowlist makes network exposure review repeatable instead of relying on memory.",
                "Run on the host or provide socket fixtures during development.",
                scored=False,
            )
        policy = Policy.load(ctx)
        if policy.explicit and not policy.valid:
            return Finding(
                self.check_id, self.title, self.module, Status.ERROR, Severity.MEDIUM,
                "invalid /etc/aegis/policy.json", "valid explicit host policy",
                "Aegis cannot compare public listeners against intent when the policy document is invalid.",
                "Run `aegis policy validate /etc/aegis/policy.json` and fix the reported schema errors.",
                auto_fix=False, evidence=policy.validation_errors, scored=False,
            )
        public = [s for s in sockets if s.wildcard]
        if not policy.explicit:
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.MEDIUM,
                f"{len(public)} wildcard listener(s); no explicit /etc/aegis/policy.json",
                "an explicit per-host public-listener allowlist",
                "Without a declared host role Aegis can inventory network exposure but cannot reliably call a non-sensitive listener unnecessary.",
                "Create /etc/aegis/policy.json after reviewing `aegis inventory sockets`.",
                auto_fix=False,
                evidence=[s.display() for s in public[:50]],
                scored=False,
            )
        unexpected = [s for s in public if s.port not in policy.allowed_public_ports]
        evidence = [s.display() for s in unexpected]
        return Finding(
            self.check_id,
            self.title,
            self.module,
            Status.WARN if unexpected else Status.PASS,
            Severity.MEDIUM,
            f"unexpected public ports: {', '.join(str(s.port) for s in unexpected) if unexpected else 'none'}",
            "only ports listed in /etc/aegis/policy.json -> network.allowed_public_ports",
            "Unexpected listeners often indicate forgotten test services, accidental bind-address changes, or undocumented dependencies.",
            "Review the process behind each unexpected listener. Close/rebind it or add the port to policy only if exposure is intentional.",
            auto_fix=False,
            evidence=evidence,
        )


CHECKS = [IPv4RedirectsCheck(), FirewallActiveCheck(), SensitiveListenerExposureCheck(), PublicListenerPolicyCheck()]
