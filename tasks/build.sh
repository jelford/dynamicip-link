#! /usr/bin/env bash
set -euo pipefail

tasks/check.sh
zip dist/package.zip ./*.py

echo "Package built: dist/package.zip"
