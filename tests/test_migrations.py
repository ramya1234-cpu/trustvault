from datetime import datetime, timezone
from pathlib import Path
import pytest
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import Session
from alembic.config import Config
from alembic import command

from app.audit import verify_audit_chain, GENESIS_HASH


def test_alembic_migrations_lifecycle(tmp_path):
    db_file = tmp_path / "migration_test.db"
    db_url = f"sqlite:///{db_file}"

    # 1. Prepare Alembic Config pointing to the temporary test database
    alembic_ini_path = Path(__file__).resolve().parent.parent / "alembic.ini"
    alembic_cfg = Config(str(alembic_ini_path))
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)

    # 2. Pre-populate database with baseline legacy schema (pre-migration state)
    engine = create_engine(db_url)
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                full_name VARCHAR(120) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) DEFAULT 'viewer' NOT NULL,
                is_active BOOLEAN DEFAULT 1 NOT NULL,
                created_at TIMESTAMP NOT NULL
            );
        """))
        conn.execute(text("""
            CREATE TABLE documents (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL REFERENCES users(id),
                title VARCHAR(255) NOT NULL,
                category VARCHAR(100) DEFAULT 'General' NOT NULL,
                storage_path VARCHAR(500) NOT NULL,
                created_at TIMESTAMP NOT NULL
            );
        """))
        conn.execute(text("""
            CREATE TABLE document_permissions (
                id INTEGER PRIMARY KEY,
                document_id INTEGER NOT NULL REFERENCES documents(id),
                user_id INTEGER NOT NULL REFERENCES users(id),
                can_read BOOLEAN DEFAULT 1 NOT NULL,
                can_edit BOOLEAN DEFAULT 0 NOT NULL,
                granted_by INTEGER NOT NULL REFERENCES users(id),
                created_at TIMESTAMP NOT NULL
            );
        """))
        conn.execute(text("""
            CREATE TABLE audit_events (
                id INTEGER PRIMARY KEY,
                actor_id INTEGER REFERENCES users(id),
                action VARCHAR(80) NOT NULL,
                document_id INTEGER,
                details TEXT DEFAULT '' NOT NULL,
                created_at TIMESTAMP NOT NULL
            );
        """))

        # Insert historical data without hash columns
        conn.execute(text("""
            INSERT INTO users (id, email, full_name, password_hash, role, is_active, created_at)
            VALUES (1, 'mig_user@example.com', 'Mig User', 'hash', 'owner', 1, '2026-10-20 12:00:00');
        """))
        conn.execute(text("""
            INSERT INTO documents (id, owner_id, title, category, storage_path, created_at)
            VALUES (1, 1, 'Legacy Document', 'Legal', 'legacy.pdf', '2026-10-20 12:05:00');
        """))
        conn.execute(text("""
            INSERT INTO audit_events (id, actor_id, action, document_id, details, created_at)
            VALUES (1, 1, 'document_uploaded', 1, 'Uploaded legacy doc', '2026-10-20 12:05:00'),
                   (2, 1, 'document_shared', 1, 'Shared legacy doc', '2026-10-20 12:10:00');
        """))

    # 3. Stamp baseline migration (0001) as already applied to the legacy database
    command.stamp(alembic_cfg, "0001_initial_schema")

    # 4. Run migration upgrade to head (0002)
    command.upgrade(alembic_cfg, "head")

    # 5. Verify columns were added
    inspector = inspect(engine)
    doc_cols = {c["name"] for c in inspector.get_columns("documents")}
    audit_cols = {c["name"] for c in inspector.get_columns("audit_events")}
    assert "updated_at" in doc_cols
    assert "prev_hash" in audit_cols
    assert "hash" in audit_cols

    # 6. Verify historical records backfill integrity
    from app.models import AuditEvent
    with Session(engine) as session:
        events = session.scalars(select(AuditEvent).order_by(AuditEvent.id.asc())).all()
        assert len(events) == 2
        assert events[0].prev_hash == GENESIS_HASH
        assert events[0].hash is not None and len(events[0].hash) == 64
        assert events[1].prev_hash == events[0].hash
        assert events[1].hash is not None and len(events[1].hash) == 64

        # Cryptographic chain verification must succeed on backfilled historical records
        res = verify_audit_chain(session)
        assert res["is_valid"] is True
        assert res["total_events"] == 2
        assert res["verified_events"] == 2

    # 7. Test migration downgrade
    command.downgrade(alembic_cfg, "0001_initial_schema")
    inspector = inspect(engine)
    doc_cols_after = {c["name"] for c in inspector.get_columns("documents")}
    audit_cols_after = {c["name"] for c in inspector.get_columns("audit_events")}
    assert "updated_at" not in doc_cols_after
    assert "prev_hash" not in audit_cols_after
    assert "hash" not in audit_cols_after

    # 8. Test upgrading back to head
    command.upgrade(alembic_cfg, "head")
    inspector = inspect(engine)
    assert "updated_at" in {c["name"] for c in inspector.get_columns("documents")}
    engine.dispose()
