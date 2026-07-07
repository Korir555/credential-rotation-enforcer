# Credential Rotation Enforcer

`credential_rotation_enforcer.py` is a defensive CLI that checks whether known credentials comply with a rotation policy. It reads metadata only, never credential values.

## Inventory format

Create a JSON file with a list of credentials:

```json
[
  {
    "name": "prod-deploy-token",
    "provider": "github",
    "owner": "platform",
    "created_at": "2026-04-01",
    "last_rotated_at": "2026-04-01",
    "rotation_days": 90,
    "expires_at": "2026-08-01"
  }
]
```

You can also wrap the list in an object:

```json
{
  "credentials": []
}
```

## Usage

Check an inventory with a 90-day default rotation policy:

```bash
python3 credential_rotation_enforcer.py credentials.json
```

Emit JSON for CI:

```bash
python3 credential_rotation_enforcer.py credentials.json --json
```

Fail on warnings as well as overdue or expired credentials:

```bash
python3 credential_rotation_enforcer.py credentials.json --fail-on-warning
```

## Statuses

- `ok`: credential is inside the rotation window.
- `rotation_due_soon`: credential is within the warning window.
- `rotation_overdue`: credential exceeded its rotation window.
- `expiring_soon`: credential expires within the warning window.
- `expired`: credential is already expired.
- `missing_metadata`: credential lacks `created_at` or `last_rotated_at`.

## Recommended workflow

1. Keep the inventory in a private security repository or generate it from provider APIs.
2. Run this CLI in CI on a schedule.
3. Route failures to the credential owner.
4. Rotate the credential in the provider, update consuming systems, then update `last_rotated_at`.
