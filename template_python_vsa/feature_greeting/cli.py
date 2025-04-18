import typer

from template_python_vsa.config import settings  # Example using global config

from .services import GreetingService

app = typer.Typer()


def run():
    """Example CLI command for the greeting feature."""
    service = GreetingService()
    message = service.generate_greeting("CLI User")
    print(f"Running VSA template CLI command from {settings.APP_TITLE}...")
    print(message)


if __name__ == "__main__":
    # This allows running the script directly using 'python -m'
    run()
