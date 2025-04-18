import pytest
from fastapi import status
from httpx import ASGITransport, AsyncClient

from template_python_vsa.main import app  # Test against the main app

pytestmark = pytest.mark.asyncio

# Remove the client fixture
# @pytest.fixture(scope="function")
# async def client() -> AsyncClient:
#     async with AsyncClient(app=app, base_url="http://test") as client_instance:
#         yield client_instance


async def test_greet_user():  # Remove client argument
    # Use the recommended transport argument
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/greet/Alice")
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {"message": "Hello, Alice!"}


async def test_greet_anonymous():  # Remove client argument, keep internal client
    # Use the recommended transport argument
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/greet/")
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {"message": "Hello, anonymous!"}
