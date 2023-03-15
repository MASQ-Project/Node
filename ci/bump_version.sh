#!/bin/bash -xv

if [ $# != 1 ]
then
     echo "Please provide version as the first argument"
     exit 1
fi

version=$1
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
file=Cargo.toml
final_exit_code=0

declare -a crates=(
  "automap"
  "dns_utility"
  "masq"
  "masq_lib"
  "multinode_integration_tests"
  "node"
  "port_exposer"
)
declare -a failed_crates

bump_version() {
  pushd """$CI_DIR""/../$1"

  sed -i '3s/version = .*/version = "'"$version"'"/' $file
  cargo generate-lockfile
  exit_code="$?"
  if [[ "$exit_code" != "0" ]]; then
      final_exit_code=1
      failed_crates+=($1)
  fi

  popd
}

for crate in "${crates[@]}"
do
   :
   bump_version "$crate"
done

if [[ "${#failed_crates[@]}" != "0" ]]; then
  echo "Failed to generate lockfile for ${#failed_crates[@]} crates: ${failed_crates[*]}"
else
  echo "The version number has been changed to $1."
fi

exit $final_exit_code
