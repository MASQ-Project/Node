#!/bin/bash
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
cp "$CI_DIR/../node/target/release/MASQNode" .
cp "$CI_DIR/../node/target/release/masq" .
cp "$CI_DIR/../dns_utility/target/release/dns_utility" .
