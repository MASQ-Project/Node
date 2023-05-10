#!/bin/bash

if [ $# != 1 ]
then
     echo "Please provide version as the first argument"
     exit 1
fi

version="$1"
regex="^[0-9]+\.[0-9]+\.[0-9]+$"

if [[ $version =~ $regex ]]; then
  echo "Changing to the version number $version"
else
  echo "Invalid version number"
  exit 1
fi

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
pushd "$CI_DIR/../"

echo "Searching for crates..."

crates=($(find . -type d -exec bash -c '[ -f "$0"/Cargo.toml ]' '{}' \; -print))

#crates=(./automap ./dns_utility ./multinode_integration_tests ./masq_lib ./masq ./port_exposer ./node)

if [[ "${#crates[@]}" == "0" ]]; then
  echo "No crates found."
  exit 1
else
  echo "Found ${#crates[@]} crate(s): ${crates[*]}"
fi

final_exit_code=0
declare -a grep_failures
declare -a lockfile_failures

find_and_replace() {
  file=Cargo.toml

  # Catches every `version` that begins a line and doesn't end with a comma.
  find_pattern='^version\s*=.*[^,]\s*$'
  replace_pattern='s/'$find_pattern'/version = "'"$version"'"/'

  grep -q "$find_pattern" "$file" && sed -i "$replace_pattern" "$file"
  exit_code=$?
  if [[ $exit_code != 0 ]]; then
    final_exit_code=1
    grep_failures+=($1)
  fi
}

update_lockfile() {
  cargo update --workspace
  exit_code=$?
  if [[ $exit_code != 0 ]]; then
    final_exit_code=1
    lockfile_failures+=($1)
  fi

  return $exit_code
}

for crate in "${crates[@]}"
do
  pushd "$crate"
  find_and_replace "$crate"
  popd
done


for crate in "${crates[@]}"
do
  pushd "$crate"
  update_lockfile "$crate"
  popd
done

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'

# Reset
NC='\033[0m'

if [[ $final_exit_code != 0 ]]; then
  [[ "${#grep_failures[@]}" != "0" ]] && echo -e "${RED}Failed to find 'version' for ${#grep_failures[@]} crate(s): ${grep_failures[*]}"
  [[ "${#lockfile_failures[@]}" != "0" ]] && echo -e "${RED}Failed to generate lockfile for ${#lockfile_failures[@]} crate(s): ${lockfile_failures[*]}"
else
  echo -e "${GREEN}The version number has been changed to $version."
fi

exit $final_exit_code
