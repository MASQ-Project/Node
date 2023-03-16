#!/bin/bash

if [ $# != 1 ]
then
     echo "Please provide version as the first argument"
     exit 1
fi

echo "Searching for crates..."

crates=($(find . -type d -exec sh -c '[ -f "$0"/Cargo.toml ]' '{}' \; -print))

if [[ "${#crates[@]}" == "0" ]]; then
  echo "No crates found."
  exit 1
else
  echo "Found ${#crates[@]} crate(s): ${crates[*]}"
fi

version="$1"
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
file=Cargo.toml
final_exit_code=0

declare -a grep_failures
declare -a lockfile_failures

bump_version() {
  # Catches every `version` that begins a line and doesn't end with a comma.
  find_pattern='^version\s*=.*[^,]\s*$'
  replace_pattern='s/'$find_pattern'/version = "'"$version"'"/'

  grep -q "$find_pattern" "$file" && sed -i "$replace_pattern" "$file"
  exit_code="$?"
  if [[ "$exit_code" != "0" ]]; then
    final_exit_code=1
    grep_failures+=($1)
    return
  fi

  cargo generate-lockfile
  exit_code="$?"
  if [[ "$exit_code" != "0" ]]; then
    final_exit_code=1
    lockfile_failures+=($1)
  fi
}

for crate in "${crates[@]}"
do
  pushd "$CI_DIR/../$crate"
  bump_version "$crate"
  popd
done

if [[ $final_exit_code != 0 ]]; then
  [[ "${#grep_failures[@]}" != "0" ]] && echo "Failed to find 'version' for ${#grep_failures[@]} crate(s): ${grep_failures[*]}"
  [[ "${#lockfile_failures[@]}" != "0" ]] && echo "Failed to generate lockfile for ${#lockfile_failures[@]} crate(s): ${lockfile_failures[*]}"
else
  echo "The version number has been changed to $version."
fi

exit $final_exit_code
