#!/bin/bash -xv

version=$1
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
file=Cargo.toml
final_exit_code=0

declare -a failed_crates

bump_version() {
  pushd "$1"

  sed -i '3s/version = .*/version = "'"$version"'"/' $file
  cargo generate-lockfile
  exit_code="$?"
  if [[ "$exit_code" != "0" ]]; then
      final_exit_code=1
      failed_crates+=($(basename $1))
  fi

  popd
}

bump_version "$CI_DIR"/../automap
bump_version "$CI_DIR"/../masq_lib
bump_version "$CI_DIR"/../node
bump_version "$CI_DIR"/../dns_utility
bump_version "$CI_DIR"/../masq
bump_version "$CI_DIR"/../multinode_integration_tests
bump_version "$CI_DIR"/../port_exposer

if [[ "${#failed_crates[@]}" != "0" ]]; then
  echo "Failed to generate lockfile for ${#failed_crates[@]} crates: ${failed_crates[*]}"
else
  echo "The version number has been changed to $1."
fi

exit $final_exit_code
