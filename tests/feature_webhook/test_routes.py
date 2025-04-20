import hashlib
import hmac
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException, status
from httpx import ASGITransport, AsyncClient

from template_python_vsa.config import Settings
from template_python_vsa.main import app  # Test against the main app

# Mark async tests individually instead of using pytestmark


# --- Test Fixtures ---
@pytest.fixture
def test_secret() -> str:
    """Provides the test webhook secret."""
    return "test-secret-123"


@pytest.fixture
def mock_settings(test_secret: str) -> Settings:
    """Fixture for mock settings with the test secret."""
    return Settings(GITHUB_WEBHOOK_SECRET=test_secret)


@pytest.fixture(autouse=True)
def override_settings(mock_settings: Settings):
    """Automatically override settings dependency for tests in this module."""
    # This uses FastAPI's dependency overrides

    # Patch the settings object directly where it's imported in services
    with patch(
        "template_python_vsa.feature_webhook.services.settings", mock_settings
    ):
        yield


# --- Helper Functions ---
def generate_signature(secret: str, payload: bytes) -> str:
    """Generates the expected HMAC-SHA256 signature."""
    signature_bytes = bytes(secret, "utf-8")
    hasher = hmac.new(signature_bytes, payload, hashlib.sha256)
    return f"sha256={hasher.hexdigest()}"


# --- Test Cases ---
@pytest.mark.asyncio
async def test_github_webhook_valid_signature_pull_request(
    test_secret: str,
):
    """Test the webhook endpoint with a valid signature for pull_request."""
    payload = {"action": "opened", "number": 1}
    payload_bytes = str(payload).replace("'", '"').encode("utf-8")  # JSON valid bytes
    signature = generate_signature(test_secret, payload_bytes)

    headers = {
        "X-Hub-Signature-256": signature,
        "X-GitHub-Event": "pull_request",
        "Content-Type": "application/json",
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/webhook/github", content=payload_bytes, headers=headers
        )

    assert response.status_code == status.HTTP_202_ACCEPTED
    assert "Webhook received and accepted" in response.json()["message"]
    assert "Processed pull_request event: action=opened" in response.json()["message"]


@pytest.mark.asyncio
async def test_github_webhook_valid_signature_issue_comment(
    test_secret: str,
):
    """Test the webhook endpoint with a valid signature for issue_comment."""
    payload = {"action": "created", "issue": {"number": 2}, "comment": {"id": 123}}
    payload_bytes = str(payload).replace("'", '"').encode("utf-8")
    signature = generate_signature(test_secret, payload_bytes)

    headers = {
        "X-Hub-Signature-256": signature,
        "X-GitHub-Event": "issue_comment",
        "Content-Type": "application/json",
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/webhook/github", content=payload_bytes, headers=headers
        )

    assert response.status_code == status.HTTP_202_ACCEPTED
    assert "Webhook received and accepted" in response.json()["message"]
    assert "Processed issue_comment event: action=created" in response.json()["message"]


@pytest.mark.asyncio
async def test_github_webhook_valid_signature_unhandled_event(
    test_secret: str,
):
    """Test the webhook endpoint with a valid signature but unhandled event."""
    payload = {"zen": "Keep it simple"}
    payload_bytes = str(payload).replace("'", '"').encode("utf-8")
    signature = generate_signature(test_secret, payload_bytes)

    headers = {
        "X-Hub-Signature-256": signature,
        "X-GitHub-Event": "ping",  # Unhandled event type
        "Content-Type": "application/json",
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/webhook/github", content=payload_bytes, headers=headers
        )

    assert response.status_code == status.HTTP_202_ACCEPTED
    assert "Received unhandled event type: ping" in response.json()["message"]


@pytest.mark.asyncio
async def test_github_webhook_invalid_signature(test_secret: str):
    """Test the webhook endpoint with an invalid signature."""
    payload = {"action": "opened", "number": 1}
    payload_bytes = str(payload).replace("'", '"').encode("utf-8")
    invalid_signature = "sha256=invalid"

    headers = {
        "X-Hub-Signature-256": invalid_signature,
        "X-GitHub-Event": "pull_request",
        "Content-Type": "application/json",
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/webhook/github", content=payload_bytes, headers=headers
        )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Invalid signature."


@pytest.mark.asyncio
async def test_github_webhook_missing_signature():
    """Test the webhook endpoint with a missing signature header."""
    payload = {"action": "opened", "number": 1}
    payload_bytes = str(payload).replace("'", '"').encode("utf-8")

    headers = {
        # Missing X-Hub-Signature-256
        "X-GitHub-Event": "pull_request",
        "Content-Type": "application/json",
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/webhook/github", content=payload_bytes, headers=headers
        )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Missing X-Hub-Signature-256 header" in response.json()["detail"]


@pytest.mark.asyncio
async def test_github_webhook_missing_event_header(test_secret: str):
    """Test the webhook endpoint with a valid signature but missing event header."""
    payload = {"action": "opened", "number": 1}
    payload_bytes = str(payload).replace("'", '"').encode("utf-8")
    signature = generate_signature(test_secret, payload_bytes)

    headers = {
        "X-Hub-Signature-256": signature,
        # Missing X-GitHub-Event
        "Content-Type": "application/json",
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/webhook/github", content=payload_bytes, headers=headers
        )

    # Signature is valid, so it passes the dependency check.
    # The route itself handles the missing event header.
    assert response.status_code == status.HTTP_202_ACCEPTED
    assert "Accepted, but missing event type header" in response.json()["message"]


@patch(
    "template_python_vsa.feature_webhook.services.WebhookService.validate_signature",
    new_callable=AsyncMock,
)
@pytest.mark.asyncio
async def test_github_webhook_validation_error(mock_validate: AsyncMock):
    """Test the webhook endpoint when validation raises an unexpected error."""
    # Use HTTPException instead of generic Exception to match handling in the service
    mock_validate.side_effect = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid signature."
    )

    payload = {"action": "opened", "number": 1}
    payload_bytes = str(payload).replace("'", '"').encode("utf-8")

    headers = {
        "X-Hub-Signature-256": "sha256=dummy",  # Value doesn't matter due to mock
        "X-GitHub-Event": "pull_request",
        "Content-Type": "application/json",
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/webhook/github", content=payload_bytes, headers=headers
        )

    # The dependency raises HTTPException which FastAPI catches
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    # The detail comes from the exception raised within validate_signature
    assert "Invalid signature." in response.json()["detail"]
