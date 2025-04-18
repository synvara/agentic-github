from typing import Annotated

from fastapi import APIRouter, Depends

from .models import GreetingResponse
from .services import GreetingService

router = APIRouter(prefix="/greet", tags=["Greeting"])


# Simple dependency provider for the service within the feature slice
def get_greeting_service() -> GreetingService:
    return GreetingService()


GreetingServiceDep = Annotated[GreetingService, Depends(get_greeting_service)]


@router.get("/{name}", response_model=GreetingResponse)
async def greet_user_endpoint(
    name: str,
    service: GreetingServiceDep,
):
    """Greets the user by name."""
    message = service.generate_greeting(name)
    return GreetingResponse(message=message)


@router.get("/", response_model=GreetingResponse)
async def greet_anonymous_endpoint(
    service: GreetingServiceDep,
):
    """Greets anonymously."""
    message = service.generate_greeting("")
    return GreetingResponse(message=message)
