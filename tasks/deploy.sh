#! /usr/bin/env bash
set -euo pipefail

aws lambda update-function-code --function-name dynamicip-link --zip-file fileb://dist/package.zip
