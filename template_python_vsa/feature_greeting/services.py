# Example service - might interact with common components or be self-contained
class GreetingService:
    def generate_greeting(self, name: str) -> str:
        if not name:
            return "Hello, anonymous!"
        return f"Hello, {name}!"
