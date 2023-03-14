#!/bin/bash -xv
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
new_version=$1
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
file=Cargo.toml
final_exit_code=0

format() {
  pushd "$1"

  sed -i '3s/version = .*/version = "'$new_version'"/' $file
  echo "The version number has been changed to $1."

  popd
}

format "$CI_DIR"/../automap
format "$CI_DIR"/../masq_lib
format "$CI_DIR"/../node
format "$CI_DIR"/../dns_utility
format "$CI_DIR"/../masq
format "$CI_DIR"/../multinode_integration_tests
format "$CI_DIR"/../port_exposer

exit $final_exit_code
