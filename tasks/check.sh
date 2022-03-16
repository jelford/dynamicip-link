#! /usr/bin/env bash
set -euo pipefail

python -m compileall ./*.py
mypy ./*.py
python -m pytest tests