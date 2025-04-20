import hashlib
import hmac

import pytest
from fastapi import HTTPException, Request, status

from template_python_vsa.config import Settings
from template_python_vsa.feature_webhook.services import WebhookService

# Mark only the async tests with pytest.mark.asyncio
# Regular synchronous tests don't need the mark


@pytest.fixture
def mock_settings() -> Settings:
    """Fixture for mock settings."""
    return Settings(GITHUB_WEBHOOK_SECRET="test-secret")


@pytest.fixture
def webhook_service(mock_settings: Settings) -> WebhookService:
    """Fixture for WebhookService."""
    return WebhookService(config=mock_settings)


@pytest.mark.asyncio
async def create_mock_request(
    content: bytes, signature: str | None = None
) -> Request:
    """Helper to create a mock FastAPI Request object."""
    headers = []
    if signature:
        headers.append(
            (b"x-hub-signature-256", signature.encode("utf-8"))
        )

    scope = {
        "type": "http",
        "method": "POST",
        "headers": headers,
        "path": "/api/webhook/github",
        "query_string": b"",
    }

    request = Request(scope)

    # We'll patch the request with a custom _receive method to return the body
    async def mocked_receive():
        return {"type": "http.request", "body": content, "more_body": False}

    request._receive = mocked_receive
    return request


def generate_signature(secret: str, payload: bytes) -> str:
    """Generates the expected HMAC-SHA256 signature."""
    signature_bytes = bytes(secret, "utf-8")
    hasher = hmac.new(signature_bytes, payload, hashlib.sha256)
    return f"sha256={hasher.hexdigest()}"


@pytest.mark.asyncio
async def test_validate_signature_valid(
    webhook_service: WebhookService, mock_settings: Settings
):
    """Test signature validation with a valid signature."""
    payload = b'{"key": "value"}'
    secret = mock_settings.GITHUB_WEBHOOK_SECRET
    signature = generate_signature(secret, payload)
    request = await create_mock_request(payload, signature)

    # Should not raise an exception
    await webhook_service.validate_signature(request, signature)


@pytest.mark.asyncio
async def test_validate_signature_missing_header(webhook_service: WebhookService):
    """Test signature validation with a missing header."""
    payload = b'{"key": "value"}'
    request = await create_mock_request(payload, None)

    with pytest.raises(HTTPException) as exc_info:
        await webhook_service.validate_signature(request, None)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Missing X-Hub-Signature-256 header" in exc_info.value.detail


@pytest.mark.asyncio
async def test_validate_signature_invalid_signature(
    webhook_service: WebhookService, mock_settings: Settings
):
    """Test signature validation with an invalid signature."""
    payload = b'{"key": "value"}'
    # Generate an invalid signature
    invalid_signature = f"sha256={'a' * 64}"  # Incorrect hash
    request = await create_mock_request(payload, invalid_signature)

    with pytest.raises(HTTPException) as exc_info:
        await webhook_service.validate_signature(request, invalid_signature)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid signature" in exc_info.value.detail


@pytest.mark.asyncio
async def test_validate_signature_no_secret_configured():
    """Test signature validation when the server secret is not configured."""
    payload = b'{"key": "value"}'
    # Configure service with empty secret
    no_secret_settings = Settings(GITHUB_WEBHOOK_SECRET="")
    service = WebhookService(config=no_secret_settings)
    signature = generate_signature("any-secret", payload)  # A signature exists
    request = await create_mock_request(payload, signature)

    with pytest.raises(HTTPException) as exc_info:
        await service.validate_signature(request, signature)

    # Should still return 401, but log indicates missing server secret
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid signature" in exc_info.value.detail


@pytest.mark.asyncio
async def test_validate_signature_tampered_payload(
    webhook_service: WebhookService, mock_settings: Settings
):
    """Test signature validation with payload different from signed one."""
    original_payload = b'{"key": "value"}'
    tampered_payload = b'{"key": "tampered"}'
    secret = mock_settings.GITHUB_WEBHOOK_SECRET
    # Signature generated for the original payload
    signature = generate_signature(secret, original_payload)
    # Request contains the tampered payload but the original signature
    request = await create_mock_request(tampered_payload, signature)

    with pytest.raises(HTTPException) as exc_info:
        await webhook_service.validate_signature(request, signature)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid signature" in exc_info.value.detail


def test_process_webhook_pull_request(webhook_service: WebhookService):
    """Test processing a pull_request event."""
    payload = {"action": "opened", "number": 123}
    result = webhook_service.process_webhook("pull_request", payload)
    assert result == "Processed pull_request event: action=opened"


def test_process_webhook_issue_comment(webhook_service: WebhookService):
    """Test processing an issue_comment event."""
    payload = {
        "action": "created",
        "issue": {"number": 456},
        "comment": {"id": 789},
    }
    result = webhook_service.process_webhook("issue_comment", payload)
    assert result == "Processed issue_comment event: action=created"


def test_process_webhook_unhandled_event(webhook_service: WebhookService):
    """Test processing an unhandled event type."""
    payload = {"data": "some_data"}
    result = webhook_service.process_webhook("ping", payload)
    assert result == "Received unhandled event type: ping"
