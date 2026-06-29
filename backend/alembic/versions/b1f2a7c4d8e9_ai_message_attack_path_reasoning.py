"""ai_message attack_path + reasoning; ATTACK_PATH/THREAT_SCENARIO use cases

Revision ID: b1f2a7c4d8e9
Revises: 3d6a9e9ba513
Create Date: 2026-06-28 12:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b1f2a7c4d8e9"
down_revision: Union[str, None] = "3d6a9e9ba513"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# New AIUseCase values backing the defensive attack-path / threat-scenario features.
_NEW_USE_CASES = ("ATTACK_PATH", "THREAT_SCENARIO")


def upgrade() -> None:
    bind = op.get_bind()
    # Extend the native enum type so use_case columns accept the new values.
    if bind.dialect.name == "postgresql":
        for value in _NEW_USE_CASES:
            op.execute(f"ALTER TYPE aiusecase ADD VALUE IF NOT EXISTS '{value}'")

    op.add_column("ai_message", sa.Column("attack_path", sa.JSON(), nullable=True))
    op.add_column("ai_message", sa.Column("reasoning", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("ai_message", "reasoning")
    op.drop_column("ai_message", "attack_path")
    # NOTE: PostgreSQL cannot drop individual enum labels; the added
    # ATTACK_PATH/THREAT_SCENARIO values are left in the aiusecase type.
