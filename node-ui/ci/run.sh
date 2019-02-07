#!/usr/bin/env bash

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

"${CI_DIR}/build.sh"
yarn start
