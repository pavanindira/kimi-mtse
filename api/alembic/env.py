"""
alembic/env.py — Alembic migration environment.

Uses the sync DATABASE_URL (psycopg2) for migrations since Alembic does not
support asyncpg natively. The async engine in database.py is used at runtime.
"""

from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from config import settings
from database import Base

# Pull in all models so Base.metadata is populated
import models  # noqa: F401

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline():
    context.configure(
        url=settings.sync_database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={'paramstyle': 'named'},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    cfg = config.get_section(config.config_ini_section, {})
    cfg['sqlalchemy.url'] = settings.sync_database_url
    connectable = engine_from_config(
        cfg, prefix='sqlalchemy.',
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection,
                          target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
