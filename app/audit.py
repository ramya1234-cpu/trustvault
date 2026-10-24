import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditEvent, utc_now

GENESIS_HASH = "0" * 64


def format_canonical_datetime(dt: datetime) -> str:
    """Format datetime to canonical UTC ISO representation with Z suffix."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def compute_event_hash(
    *,
    actor_id: int | None,
    action: str,
    document_id: int | None,
    details: str,
    created_at: datetime,
    prev_hash: str,
) -> str:
    """Compute deterministic SHA-256 hash using canonical JSON representation."""
    canonical_payload = {
        "action": action,
        "actor_id": actor_id,
        "created_at": format_canonical_datetime(created_at),
        "details": details,
        "document_id": document_id,
        "prev_hash": prev_hash,
    }
    encoded = json.dumps(
        canonical_payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def record_audit_event(
    db: Session,
    *,
    actor_id: int | None,
    action: str,
    document_id: int | None = None,
    details: str = "",
    timestamp: datetime | None = None,
) -> AuditEvent:
    """Create a new tamper-evident audit event linked to the previous event hash."""
    latest_event = db.scalar(
        select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)
    )

    prev_hash = (
        latest_event.hash
        if (latest_event and latest_event.hash)
        else GENESIS_HASH
    )

    event_time = timestamp or utc_now()
    entry_hash = compute_event_hash(
        actor_id=actor_id,
        action=action,
        document_id=document_id,
        details=details,
        created_at=event_time,
        prev_hash=prev_hash,
    )

    event = AuditEvent(
        actor_id=actor_id,
        action=action,
        document_id=document_id,
        details=details,
        created_at=event_time,
        prev_hash=prev_hash,
        hash=entry_hash,
    )
    db.add(event)
    db.flush()
    return event


def verify_audit_chain(db: Session) -> dict:
    """Verify cryptographic integrity of all audit events from genesis to the latest event.

    Detects modified event fields, altered hashes, deleted events, and reordered events.
    Limitations:
        Provides tamper evidence against application and record-level changes.
        Does not protect against a database superuser who rewrites records and recalculates all hashes.
    """
    events = db.scalars(
        select(AuditEvent).order_by(AuditEvent.id.asc())
    ).all()

    if not events:
        return {
            "is_valid": True,
            "total_events": 0,
            "verified_events": 0,
            "message": "Audit chain is empty and valid.",
            "tampered_event_id": None,
        }

    expected_prev_hash = GENESIS_HASH
    verified_count = 0

    for event in events:
        # Check linkage to previous event
        if event.prev_hash != expected_prev_hash:
            return {
                "is_valid": False,
                "total_events": len(events),
                "verified_events": verified_count,
                "message": f"Broken chain link at event ID {event.id}: previous hash mismatch.",
                "tampered_event_id": event.id,
            }

        # Check content integrity by recalculating the hash
        calculated_hash = compute_event_hash(
            actor_id=event.actor_id,
            action=event.action,
            document_id=event.document_id,
            details=event.details,
            created_at=event.created_at,
            prev_hash=event.prev_hash or GENESIS_HASH,
        )

        if event.hash != calculated_hash:
            return {
                "is_valid": False,
                "total_events": len(events),
                "verified_events": verified_count,
                "message": f"Tampered event content detected at event ID {event.id}.",
                "tampered_event_id": event.id,
            }

        expected_prev_hash = event.hash
        verified_count += 1

    return {
        "is_valid": True,
        "total_events": len(events),
        "verified_events": verified_count,
        "message": f"Audit chain verified successfully across {len(events)} events.",
        "tampered_event_id": None,
    }
