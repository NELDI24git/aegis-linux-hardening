# Remediation safety model

Aegis remediation is transaction-oriented. The core rule is: **do not change a control unless Aegis knows how to back it up, validate the new state, and restore the previous state.**

## Generic registry

Every supported fix is registered by check ID, domain, setting, target value, and risk class. `aegis list-fixes` shows the current registry. A single `aegis fix` invocation may contain checks from several domains; they are committed as one transaction.

## Managed files

Aegis currently owns only these drop-ins:

- `/etc/ssh/sshd_config.d/00-aegis-hardening.conf`
- `/etc/sysctl.d/90-aegis-hardening.conf`

It does not rewrite the distribution's primary configuration files when a supported drop-in mechanism is available.

## Runtime state

Transaction manifest schema v3 records both file hashes and known runtime state. This matters for controls such as sysctl: restoring a file alone would not restore the running kernel value.

On rollback Aegis:

1. performs conflict and backup-integrity preflight;
2. restores every file;
3. replays known runtime restoration actions in reverse order;
4. validates the restored runtime state;
5. reports a distinct failure if files were restored but runtime restoration failed.

`--files-only` exists only for advanced recovery when the normal runtime step cannot be used.

## SSH password-authentication safety

`SSH-002` is lockout-sensitive. Aegis will not disable password authentication unless all local preflight checks pass and the operator provides `--acknowledge-lockout-risk`.

Preflight verifies, among other things:

- authoritative `sshd -T` is available;
- public-key authentication is enabled;
- effective `AuthenticationMethods` does not obviously require password/keyboard-interactive authentication;
- host policy does not require password authentication;
- at least one non-root administrator is declared in policy or found in `sudo`/`wheel`;
- that administrator has a non-empty, non-group/world-writable authorized-keys file with plausible ownership.

This is **not proof of remote reachability**. It cannot prove that the key held by the operator works through a bastion, firewall, IAM layer, `Match` block, or other path-specific control. Keep a second tested administrative session open before applying lockout-sensitive changes.
