"""ai_message.intent (triage / response intent)

Revision ID: c4e7f1a2b3d8
Revises: b1f2a7c4d8e9
Create Date: 2026-06-29 12:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c4e7f1a2b3d8"
down_revision: Union[str, None] = "b1f2a7c4d8e9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Plain string (not a DB enum) so new intent labels never require a migration.
    op.add_column(
        "ai_message",
        sa.Column("intent", sa.String(), nullable=False, server_default="analysis"),
    )


def downgrade() -> None:
    op.drop_column("ai_message", "intent")
