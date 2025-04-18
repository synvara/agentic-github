from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_TITLE: str = "VSA_App"
    # ... other settings
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
