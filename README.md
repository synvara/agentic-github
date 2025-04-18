# Python VSA Template

A template project demonstrating Vertical Slice Architecture with FastAPI, uv, and ruff.

## Using This Template

This template is pre-configured. If you were adapting it for a _new_ project, you would typically:

1.  **Rename Directory:** Rename the `template_python_vsa` directory to your desired package name (e.g., `my_new_project`). Follow standard Python package naming conventions (lowercase, underscores).
2.  **Update `pyproject.toml`:**
    - Change `[project] -> name` from `"template-python-vsa"` to your project's name (e.g., `"my-new-project"`).
    - Update `[tool.hatch.build.targets.wheel] -> packages` from `["template_python_vsa"]` to `["my_new_project"]`.
    - Update `[tool.ruff.lint.isort] -> known-first-party` from `["template_python_vsa"]` to `["my_new_project"]`.
    - Update any script names and entry points in `[project.scripts]` if necessary (e.g., change `hello-vsa` target).
3.  **Update Imports:** Search for any absolute imports within the Python code starting with `from template_python_vsa.` and change them to use your new package name (e.g., `from my_new_project.`).

## Project Structure

- **`template_python_vsa/`**: The main Python package containing the application code.
  - **`common/`**: Code shared across multiple features (e.g., base models, utilities).
  - **`feature_*/`**: Directories representing vertical slices (e.g., `feature_greeting/`). Each contains the routes, services, models, etc., specific to that feature.
  - **`config.py`**: Application configuration management (using Pydantic Settings).
  - **`main.py`**: FastAPI application setup and entry point.
- **`tests/`**: Automated tests, mirroring the package structure.
- **`.venv/`**: Virtual environment managed by `uv` (automatically created, should be gitignored).
- **`pyproject.toml`**: Project metadata, dependencies, and tool configuration (ruff, hatch, pytest).
- **`.env.example`**: Example environment file for configuration.
- **`README.md`**: This file.

## Setup and Development

1.  **Prerequisites:** Ensure you have Python (>=3.12 recommended) and `uv` installed.
2.  **Create/Sync Environment:** `uv` can manage the environment automatically. To ensure all dependencies (including development tools) are installed, run:
    ```bash
    uv sync --all-extras
    ```
    This will create a `.venv` directory if it doesn't exist and install/update packages according to `pyproject.toml` and `uv.lock`.
3.  **Activate Environment (Optional but Recommended for Shell Use):**
    ```bash
    source .venv/bin/activate
    ```
    Activating makes commands like `python`, `pytest`, `uvicorn` available directly in your shell.

## Running the Application

Use `uv run` to execute the Uvicorn server within the managed environment:

```bash
uv run uvicorn template_python_vsa.main:app --reload --host 0.0.0.0 --port 8000
```

Alternatively, if you have activated the environment:

```bash
uvicorn template_python_vsa.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`.

## Running Checks & Tests

Use `uv run` to execute development tools within the managed environment:

- **Lint & Format:**
  ```bash
  uv run ruff check . --fix
  uv run ruff format .
  ```
- **Type Check:**
  ```bash
  uv run mypy .
  ```
- **Run Tests:**
  ```bash
  uv run pytest
  ```

## Running CLI Scripts

Scripts defined in `pyproject.toml` (`[project.scripts]`) can be run using `uv run`:

```bash
uv run hello-vsa
```
