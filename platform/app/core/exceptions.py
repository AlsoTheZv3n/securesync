"""Custom exceptions for SecureSync platform.

Use these instead of raw HTTPException so handlers can map them consistently
and external API failures never leak stack traces to clients.
"""

from fastapi import status


class SecureSyncError(Exception):
    """Base class for all SecureSync application errors."""

    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    message: str = "Internal server error"

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.message)
        if message:
            self.message = message


class AuthenticationError(SecureSyncError):
    status_code = status.HTTP_401_UNAUTHORIZED
    message = "Invalid credentials"


class PermissionDeniedError(SecureSyncError):
    status_code = status.HTTP_403_FORBIDDEN
    message = "Insufficient permissions"


class TenantIsolationError(PermissionDeniedError):
    message = "Resource does not belong to current tenant"


class ResourceNotFoundError(SecureSyncError):
    status_code = status.HTTP_404_NOT_FOUND
    message = "Resource not found"


class ValidationError(SecureSyncError):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    message = "Validation failed"


class ExternalServiceError(SecureSyncError):
    status_code = status.HTTP_502_BAD_GATEWAY
    message = "Upstream service unavailable"


class RateLimitError(SecureSyncError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    message = "Too many requests"
