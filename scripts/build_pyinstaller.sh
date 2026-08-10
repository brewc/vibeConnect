#!/usr/bin/env sh
set -eu

python -m build
PYINSTALLER_CONFIG_DIR="${PYINSTALLER_CONFIG_DIR:-.pyinstaller-cache}"
export PYINSTALLER_CONFIG_DIR

pyinstaller --onefile --specpath build/pyinstaller -n vibeconnect-server src/server/main.py
pyinstaller --onefile --specpath build/pyinstaller -n vibeconnect-agent src/agent/main.py
