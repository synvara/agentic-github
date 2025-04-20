from fastapi import FastAPI

from template_python_vsa.config import settings
from template_python_vsa.feature_greeting import routes as greeting_routes
from template_python_vsa.feature_webhook import routes as webhook_routes

# Uncomment the following line if you have an 'items' feature
# from template_python_vsa.feature_items import routes as item_routes

app = FastAPI(
    title=settings.APP_TITLE,
    description="Example VSA API",
    version="0.1.0",
)

# Include feature routers
app.include_router(greeting_routes.router)
app.include_router(webhook_routes.router)
# app.include_router(item_routes.router)


@app.get("/", tags=["Health Check"])
async def root():
    return {"message": f"Welcome to {settings.APP_TITLE}"}
