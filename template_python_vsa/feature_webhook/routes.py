import logging
from typing import Any

from fastapi import APIRouter, Depends, Header, Request, status

from .models import WebhookResponse
from .services import SignatureVerifierDep, WebhookServiceDep

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/webhook",
    tags=["Webhook"],
    # Apply signature verification dependency to all routes in this router
    dependencies=[Depends(SignatureVerifierDep)],
)


@router.post(
    "/github",
    response_model=WebhookResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def handle_github_webhook(
    request: Request,
    payload: dict[str, Any],  # Use dict for flexibility, or a specific Pydantic model
    service: WebhookServiceDep,
    x_github_event: str | None = Header(None),
):
    """
    Handles incoming GitHub webhooks after signature validation.

    Processes 'pull_request' and 'issue_comment' events.
    """
    if not x_github_event:
        logger.warning("Missing X-GitHub-Event header")
        # Signature was validated, but event type is missing.
        # Decide how to handle this - maybe accept but log warning?
        return WebhookResponse(message="Accepted, but missing event type header.")

    logger.info(
        "Received valid webhook. Event: %s, Payload keys: %s",
        x_github_event,
        list(payload.keys()),
    )

    # Process the event using the service
    processing_message = service.process_webhook(x_github_event, payload)

    return WebhookResponse(
        message=f"Webhook received and accepted. {processing_message}"
    )
