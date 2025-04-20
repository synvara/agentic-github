from typing import Any

from pydantic import BaseModel


class WebhookPayload(BaseModel):
    """Generic model for webhook payloads."""

    # Define specific fields if needed, or use Extra.allow for flexibility
    # For now, we'll just accept any dictionary structure.
    # Example fields for specific events could be added later.
    # action: Optional[str] = None
    # pull_request: Optional[dict[str, Any]] = None
    # issue: Optional[dict[str, Any]] = None
    # comment: Optional[dict[str, Any]] = None
    data: dict[str, Any]


class WebhookResponse(BaseModel):
    """Response model for the webhook endpoint."""

    message: str
