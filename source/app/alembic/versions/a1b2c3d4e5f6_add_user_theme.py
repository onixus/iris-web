"""add user_theme column

Revision ID: a1b2c3d4e5f6
Revises: (b664ca1203a4, d5a720d1b99b)
Create Date: 2026-02-25
"""
from alembic import op
import sqlalchemy as sa

revision = 'a1b2c3d4e5f6'
down_revision = ('b664ca1203a4', 'd5a720d1b99b')
branch_labels = None
depends_on = None


def upgrade():
    # Add user_theme column: 'light' | 'dark' | 'pride'  (default: light)
    op.add_column('user', sa.Column('user_theme', sa.String(16), nullable=True))
    # Migrate existing in_dark_mode=True users to theme='dark'
    op.execute("""
        UPDATE "user"
        SET user_theme = CASE
            WHEN in_dark_mode = TRUE THEN 'dark'
            ELSE 'light'
        END
        WHERE user_theme IS NULL
    """)


def downgrade():
    op.drop_column('user', 'user_theme')
