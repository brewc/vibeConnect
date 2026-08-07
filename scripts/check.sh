#!/usr/bin/env sh
set -eu

if [ -x ".venv/bin/python" ]; then
    PYTHON=".venv/bin/python"
else
    PYTHON="${PYTHON:-python3}"
fi

"$PYTHON" -m ruff format --check src tests
"$PYTHON" -m ruff check src tests
"$PYTHON" -m mypy src tests
"$PYTHON" -m pytest -q
