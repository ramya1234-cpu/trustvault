"""Add updated_at to documents and SHA-256 hash-chain columns to audit_events with historical backfill

Revision ID: 0002_add_updated_at_and_audit_hash_chain
Revises: 0001_initial_schema
Create Date: 2026-10-24 18:35:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import table, column

from app.audit import GENESIS_HASH, compute_event_hash


revision: str = "0002_add_updated_at_and_audit_hash_chain"
down_revision: Union[str, Sequence[str], None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # 1. Add documents.updated_at if not present
    doc_cols = {col["name"] for col in inspector.get_columns("documents")}
    if "updated_at" not in doc_cols:
        op.add_column(
            "documents",
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        )

    # 2. Add audit_events.prev_hash and audit_events.hash if not present
    audit_cols = {col["name"] for col in inspector.get_columns("audit_events")}
    if "prev_hash" not in audit_cols:
        op.add_column(
            "audit_events",
            sa.Column("prev_hash", sa.String(length=64), server_default="0" * 64, nullable=True),
        )
    if "hash" not in audit_cols:
        op.add_column(
            "audit_events",
            sa.Column("hash", sa.String(length=64), server_default="", nullable=True),
        )

    # 3. Drop foreign key constraint on audit_events.document_id if it exists
    # This ensures audit trail immutability is preserved when a document is deleted.
    fks = inspector.get_foreign_keys("audit_events")
    for fk in fks:
        if fk.get("referred_table") == "documents" or "document_id" in fk.get("constrained_columns", []):
            fk_name = fk.get("name")
            if fk_name:
                try:
                    op.drop_constraint(fk_name, "audit_events", type_="foreignkey")
                except Exception:
                    pass

    # 4. Deterministic chronological backfill of historical audit records
    audit_table = table(
        "audit_events",
        column("id", sa.Integer),
        column("actor_id", sa.Integer),
        column("action", sa.String),
        column("document_id", sa.Integer),
        column("details", sa.Text),
        column("created_at", sa.DateTime),
        column("prev_hash", sa.String),
        column("hash", sa.String),
    )

    rows = conn.execute(
        sa.select(
            audit_table.c.id,
            audit_table.c.actor_id,
            audit_table.c.action,
            audit_table.c.document_id,
            audit_table.c.details,
            audit_table.c.created_at,
            audit_table.c.prev_hash,
            audit_table.c.hash,
        ).order_by(audit_table.c.id.asc())
    ).fetchall()

    if rows:
        current_prev_hash = GENESIS_HASH
        for row in rows:
            # If hash is already present and valid, maintain continuity
            existing_hash = row.hash
            existing_prev = row.prev_hash

            if existing_hash and existing_hash != "" and existing_prev:
                current_prev_hash = existing_hash
                continue

            event_hash = compute_event_hash(
                actor_id=row.actor_id,
                action=row.action,
                document_id=row.document_id,
                details=row.details or "",
                created_at=row.created_at,
                prev_hash=current_prev_hash,
            )

            conn.execute(
                audit_table.update()
                .where(audit_table.c.id == row.id)
                .values(
                    prev_hash=current_prev_hash,
                    hash=event_hash,
                )
            )
            current_prev_hash = event_hash


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    audit_cols = {col["name"] for col in inspector.get_columns("audit_events")}
    if "hash" in audit_cols:
        op.drop_column("audit_events", "hash")
    if "prev_hash" in audit_cols:
        op.drop_column("audit_events", "prev_hash")

    doc_cols = {col["name"] for col in inspector.get_columns("documents")}
    if "updated_at" in doc_cols:
        op.drop_column("documents", "updated_at")
