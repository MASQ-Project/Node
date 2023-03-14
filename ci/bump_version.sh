#!/bin/bash -xv
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
new_version=$1
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
file=Cargo.toml
final_exit_code=0

bump_version() {
  pushd "$1"

  sed -i '3s/version = .*/version = "'$new_version'"/' $file
  cargo generate-lockfile

  popd
}

bump_version "$CI_DIR"/../automap
bump_version "$CI_DIR"/../masq_lib
bump_version "$CI_DIR"/../node
bump_version "$CI_DIR"/../dns_utility
bump_version "$CI_DIR"/../masq
bump_version "$CI_DIR"/../multinode_integration_tests
bump_version "$CI_DIR"/../port_exposer

echo "The version number has been changed to $1."
exit $final_exit_code
