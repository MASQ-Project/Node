#!/bin/bash -xv
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

final_exit_code=0

format() {
  pushd "$1"

  cargo fmt --all -- --check
  exit_code="$?"
  if [[ "$exit_code" != "0" ]]; then
      final_exit_code=1
      echo "Your code failed the formatting check. If you wish to leave the code the way it is, use the directive #[cfg_attr(rustfmt, rustfmt_skip)]"
  fi
  cargo fmt --all

  popd
}

format "$CI_DIR"/../automap
format "$CI_DIR"/../masq_lib
format "$CI_DIR"/../node
format "$CI_DIR"/../dns_utility
format "$CI_DIR"/../masq
format "$CI_DIR"/../multinode_integration_tests
format "$CI_DIR"/../port_exposer
format "$CI_DIR"/../ip_country

exit $final_exit_code
