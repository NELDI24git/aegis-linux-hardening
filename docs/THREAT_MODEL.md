# Threat model

Aegis is a **defensive host-auditing and hardening tool**. It is not a vulnerability scanner, EDR, malware detector, exploit framework, or substitute for configuration management.

## Assets protected

- remote administrative access;
- privileged local execution boundaries;
- network attack surface;
- audit/logging continuity;
- important security configuration;
- recoverability from an incorrect automated change.

## Threats considered

- accidental public exposure of local/admin/database services;
- remote brute-force-enabling SSH settings;
- unexpected UID 0 identities;
- empty password fields;
- unsafe critical-file permissions;
- writable or unexplained SUID/SGID executables;
- dangerous kernel information exposure / weakened local hardening;
- insecure shared-memory mount semantics;
- loss of logs after reboot;
- inactive expected security services;
- exposed Docker control interfaces;
- security patch latency;
- configuration drift after a trusted review;
- self-inflicted administrator lockout or configuration corruption caused by the hardening tool itself.

## Threats explicitly not solved

- zero-day vulnerabilities in services;
- malicious kernel/rootkit that lies to userspace inspection;
- compromised package repositories;
- stolen valid administrator credentials;
- cloud security-group or upstream firewall policy unless separately integrated;
- application-specific authorization flaws;
- proving that the current machine is clean before a baseline is created.

## Safety boundary

Read-only audit should be broadly usable. Automatic remediation has a much higher bar.

A remediation must have a deterministic current-state check, backup strategy, atomic or staged write, validation strategy and rollback path. Role-dependent changes such as firewall allowlists or disabling a login mechanism require explicit host intent and stronger operator confirmation.
