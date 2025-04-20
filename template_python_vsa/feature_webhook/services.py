import hashlib
import hmac
import logging
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status

from template_python_vsa.config import Settings, settings

logger = logging.getLogger(__name__)


class WebhookService:
    """Service for handling webhook logic."""

    def __init__(self, config: Settings):
        self.config = config

    async def validate_signature(
        self, request: Request, x_hub_signature_256: str | None = Header(None)
    ) -> None:
        """
        Validates the GitHub webhook signature.

        Raises:
            HTTPException: If the signature is missing or invalid.
        """
        if not x_hub_signature_256:
            logger.error("Missing X-Hub-Signature-256 header")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing X-Hub-Signature-256 header",
            )

        if not self.config.GITHUB_WEBHOOK_SECRET:
            logger.error("Webhook secret is not configured on the server.")
            # Avoid revealing that the secret is missing, treat as validation failure
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid signature.",
            )

        body = await request.body()
        try:
            signature_bytes = bytes(self.config.GITHUB_WEBHOOK_SECRET, "utf-8")
            hasher = hmac.new(signature_bytes, body, hashlib.sha256)
            computed_signature = f"sha256={hasher.hexdigest()}"

            if not hmac.compare_digest(computed_signature, x_hub_signature_256):
                logger.error(
                    "Invalid signature. Computed: %s, Received: %s",
                    computed_signature,
                    x_hub_signature_256,
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid signature.",
                )
            logger.debug("Webhook signature validated successfully.")
        except Exception as e:
            logger.exception("Error during signature validation: %s", e)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid signature.",
            ) from e

    def process_webhook(self, event_type: str, payload: dict) -> str:
        """
        Processes the validated webhook payload based on the event type.
        """
        logger.info("Processing webhook event: %s", event_type)
        # Add specific logic for different event types here
        if event_type == "pull_request":
            action = payload.get("action", "unknown")
            pr_number = payload.get("number", "unknown")
            logger.info(
                "Received pull_request event: action=%s, number=%s", action, pr_number
            )
            return f"Processed pull_request event: action={action}"
        elif event_type == "issue_comment":
            action = payload.get("action", "unknown")
            issue_number = payload.get("issue", {}).get("number", "unknown")
            comment_id = payload.get("comment", {}).get("id", "unknown")
            logger.info(
                "Received issue_comment event: action=%s, issue=%s, comment=%s",
                action,
                issue_number,
                comment_id,
            )
            return f"Processed issue_comment event: action={action}"
        else:
            logger.warning("Received unhandled event type: %s", event_type)
            return f"Received unhandled event type: {event_type}"


# Dependency provider for the service
def get_webhook_service() -> WebhookService:
    return WebhookService(config=settings)


WebhookServiceDep = Annotated[WebhookService, Depends(get_webhook_service)]


# Dependency for signature validation
async def verify_github_signature(
    request: Request,
    service: WebhookServiceDep,
    x_hub_signature_256: str | None = Header(None),
) -> None:
    """FastAPI dependency to verify the GitHub webhook signature."""
    await service.validate_signature(request, x_hub_signature_256)


# Define a callable dependency function
SignatureVerifierDep = verify_github_signature
