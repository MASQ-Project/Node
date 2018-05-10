#!/usr/bin/env bash

set -e

cd "test/fixtures"
node -r "./quibbles-requires-a-function.js" "expects-a-quibbling.js"
