#!/usr/bin/env python3
"""Credential rotation policy enforcer.

Reads a JSON inventory of credential metadata and reports credentials that are
overdue for rotation, missing rotation metadata, expired, or close to expiry.
It never reads or prints secret values.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_ROTATION_DAYS = 90
DEFAULT_WARN_DAYS = 14


@dataclasses.dataclass
class PolicyResult:
    name: str
    provider: str
    status: str
    severity: str
    message: str
    days_since_rotation: int | None
    days_until_due: int | None
    owner: str | None = None


def parse_date(value: str | None, field_name: str, credential_name: str) -> date | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError as exc:
        raise ValueError(f"{credential_name}: invalid {field_name} date {value!r}") from exc


def load_inventory(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc

    if isinstance(data, dict) and isinstance(data.get("credentials"), list):
        return data["credentials"]
    if isinstance(data, list):
        return data
    raise SystemExit("Inventory must be a JSON list or an object with a 'credentials' list.")


def evaluate_credential(
    credential: dict[str, Any],
    today: date,
    default_rotation_days: int,
    warn_days: int,
) -> PolicyResult:
    name = str(credential.get("name") or credential.get("id") or "<unnamed>")
    provider = str(credential.get("provider") or "unknown")
    owner = credential.get("owner")
    rotation_days = int(credential.get("rotation_days") or default_rotation_days)

    created_at = parse_date(credential.get("created_at"), "created_at", name)
    last_rotated_at = parse_date(credential.get("last_rotated_at"), "last_rotated_at", name)
    expires_at = parse_date(credential.get("expires_at"), "expires_at", name)

    reference_date = last_rotated_at or created_at
    if reference_date is None:
        return PolicyResult(
            name=name,
            provider=provider,
            owner=str(owner) if owner else None,
            status="missing_metadata",
            severity="high",
            message="missing created_at or last_rotated_at",
            days_since_rotation=None,
            days_until_due=None,
        )

    days_since_rotation = (today - reference_date).days
    days_until_due = rotation_days - days_since_rotation

    if expires_at is not None:
        days_until_expiry = (expires_at - today).days
        if days_until_expiry < 0:
            return PolicyResult(
                name=name,
                provider=provider,
                owner=str(owner) if owner else None,
                status="expired",
                severity="critical",
                message=f"expired {-days_until_expiry} days ago",
                days_since_rotation=days_since_rotation,
                days_until_due=days_until_due,
            )
        if days_until_expiry <= warn_days:
            return PolicyResult(
                name=name,
                provider=provider,
                owner=str(owner) if owner else None,
                status="expiring_soon",
                severity="high",
                message=f"expires in {days_until_expiry} days",
                days_since_rotation=days_since_rotation,
                days_until_due=days_until_due,
            )

    if days_until_due < 0:
        return PolicyResult(
            name=name,
            provider=provider,
            owner=str(owner) if owner else None,
            status="rotation_overdue",
            severity="high",
            message=f"rotation overdue by {-days_until_due} days",
            days_since_rotation=days_since_rotation,
            days_until_due=days_until_due,
        )

    if days_until_due <= warn_days:
        return PolicyResult(
            name=name,
            provider=provider,
            owner=str(owner) if owner else None,
            status="rotation_due_soon",
            severity="medium",
            message=f"rotation due in {days_until_due} days",
            days_since_rotation=days_since_rotation,
            days_until_due=days_until_due,
        )

    return PolicyResult(
        name=name,
        provider=provider,
        owner=str(owner) if owner else None,
        status="ok",
        severity="info",
        message=f"rotation due in {days_until_due} days",
        days_since_rotation=days_since_rotation,
        days_until_due=days_until_due,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Enforce credential rotation age and expiry policies from a JSON inventory."
    )
    parser.add_argument("inventory", help="Path to credential inventory JSON.")
    parser.add_argument("--rotation-days", type=int, default=DEFAULT_ROTATION_DAYS, help="Default max credential age.")
    parser.add_argument("--warn-days", type=int, default=DEFAULT_WARN_DAYS, help="Warn when rotation/expiry is this close.")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    parser.add_argument("--fail-on-warning", action="store_true", help="Exit non-zero on warning-level results too.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    today = datetime.now(timezone.utc).date()
    credentials = load_inventory(Path(args.inventory))
    results = [
        evaluate_credential(credential, today, args.rotation_days, args.warn_days)
        for credential in credentials
    ]

    failures = [result for result in results if result.severity in {"critical", "high"}]
    warnings = [result for result in results if result.severity == "medium"]

    if args.json:
        print(
            json.dumps(
                {
                    "checked": len(results),
                    "failures": len(failures),
                    "warnings": len(warnings),
                    "results": [dataclasses.asdict(result) for result in results],
                },
                indent=2,
            )
        )
    else:
        print(f"Checked credentials: {len(results)}")
        print(f"Failures: {len(failures)}")
        print(f"Warnings: {len(warnings)}")
        for result in results:
            owner = f" owner={result.owner}" if result.owner else ""
            print(
                f"{result.severity.upper():8} {result.provider}/{result.name} "
                f"{result.status}: {result.message}{owner}"
            )

    if failures or (args.fail_on_warning and warnings):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
