import os
import subprocess
import sys

import pytest


def test_vsa_cli_script_runs():
    try:
        # Create a copy of the current environment and remove VIRTUAL_ENV if it exists
        env = os.environ.copy()
        env.pop("VIRTUAL_ENV", None)

        # Use sys.executable to get the current Python interpreter
        python_executable = sys.executable

        result = subprocess.run(
            [python_executable, "-m", "template_python_vsa.feature_greeting.cli"],
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8",
            env=env,
        )
        assert "Running VSA template CLI command" in result.stdout
        assert "Hello, CLI User!" in result.stdout
        assert result.stderr == ""
    except subprocess.CalledProcessError as e:
        pytest.fail(f"CLI script failed:\nSTDOUT:\n{e.stdout}\nSTDERR:\n{e.stderr}")
