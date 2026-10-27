# Policy and role profiles

Policy schema v3 separates built-in role defaults from local host intent.

```json
{
  "schema_version": 3,
  "profile": "web-server",
  "network": {"allowed_public_ports": [22, 80, 443]},
  "privilege": {"allowed_suid_sgid": []},
  "ssh": {"admin_users": ["admin"], "expected_password_authentication": "disabled"},
  "controls": {"include": [], "exclude": []},
  "exceptions": []
}
```

## Inheritance

Built-in profiles provide defaults. Local fields override those defaults. Omitting `network.allowed_public_ports` means the profile's default is inherited; providing it means the local list is authoritative.

Profiles: `general`, `web-server`, `database`, `bastion`, `container-host`, `minimal`.

The `minimal` profile is an intentionally smaller high-signal control pack. Other profiles retain broad host controls but change role intent such as expected public ports.

## Control selection

`controls.include` explicitly enables named check IDs. `controls.exclude` disables named IDs. Exclusion wins over profile defaults; explicit inclusion can restore a check omitted by a profile.

CLI filtering can additionally select semantic tags, for example:

```bash
aegis audit --tag authentication
aegis audit --tag attack-surface
```

## Exceptions

Every exception requires:

- stable `check_id`;
- meaningful rationale;
- ISO `YYYY-MM-DD` expiry;
- optional ticket/change reference.

Active exceptions produce `EXEMPT`, never `PASS`. Their original result is retained in the finding metadata and they are excluded from scoring. Expired exceptions do not suppress findings.

## Public services

Role names never authorize sensitive services implicitly. In particular, the `database` profile does not approve public database ports. Expose them only through an explicit reviewed local policy.
