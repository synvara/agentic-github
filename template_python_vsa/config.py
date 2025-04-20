from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_TITLE: str = "VSA_App"
    GITHUB_WEBHOOK_SECRET: str = ""
    # ... other settings
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
