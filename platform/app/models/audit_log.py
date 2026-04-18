"""AuditLog model — append-only record of privileged actions.

Not tamper-proof by itself (ops can edit Postgres), but a strong enough
audit trail for compliance snapshots when combined with DB-level controls
(separate read-only replica, SIEM shipping). No update or delete endpoint
— rows are only inserted.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AuditLog(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "audit_logs"

    # Nullable: auth events often fire BEFORE we have tenant context
    # (failed login with wrong email), or for cross-tenant platform actions.
    tenant_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # Nullable: failed logins have no authenticated user.
    user_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Dotted action name: "tenant.create", "scan.start", "user.invite",
    # "auth.login_success", "auth.login_failed".
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Optional: the primary object this action touched.
    resource_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resource_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), nullable=True, index=True
    )

    # Request context — ip is the XFF-resolved real client.
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Arbitrary structured payload: before/after snapshots, failure reasons,
    # role-escalation attempts. Kept small by the callers (not enforced here).
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )

    def __repr__(self) -> str:
        return (
            f"<AuditLog id={self.id} action={self.action!r} "
            f"user_id={self.user_id} resource={self.resource_type}:{self.resource_id}>"
        )
