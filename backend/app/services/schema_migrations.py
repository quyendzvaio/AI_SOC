from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection


async def run_bootstrap_migrations(conn: AsyncConnection) -> None:
    # create_all creates new tables but does not alter existing tables. These guards keep local
    # Postgres volumes usable as the MVP schema evolves.
    statements = [
        "ALTER TYPE otppurpose ADD VALUE IF NOT EXISTS 'verify_notification_email'",
        "ALTER TYPE otppurpose ADD VALUE IF NOT EXISTS 'verify_imap_email'",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS firebase_uid VARCHAR(128) UNIQUE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(32) DEFAULT 'local'",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS notification_email VARCHAR(255)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_notification_email_verified BOOLEAN DEFAULT FALSE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS device_log_consent_granted_at TIMESTAMP WITH TIME ZONE",
    ]
    for statement in statements:
        await conn.execute(text(statement))
