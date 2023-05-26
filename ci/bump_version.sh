#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
#YELLOW='\033[0;33m'
#BLUE='\033[0;34m'
#MAGENTA='\033[0;35m'
#GRAY='\033[0;37m'

# Reset output color to the default
NC='\033[0m'

if [ $# != 1 ]
then
     echo "Please provide version as the first argument"
     exit 1
fi

version="$1"
regex="^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$"

if [[ $version =~ $regex ]]; then
  echo -e "${CYAN}Changing to the version number $version${NC}"
else
  echo -e "${RED}Error: Invalid version number provided.${NC}"
  echo "The version number should follow the semantic versioning format."
  echo "Please ensure the version number consists of MAJOR.MINOR.PATCH"
  echo "Example: 0.6.9 or 2.3.1"
  exit 1
fi

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
pushd "$CI_DIR/../"

echo "Searching for crates..."

crates=($(find . -type d -exec bash -c '[ -f "$0"/Cargo.toml ]' '{}' \; -print))

if [[ "${#crates[@]}" == "0" ]]; then
  echo -e "${RED}Error: No crates found."
  exit 1
else
  echo -e "${CYAN}Found ${#crates[@]} crate(s): ${crates[*]}${NC}"
fi

final_exit_code=0
declare -a grep_failures
declare -a lockfile_failures

# Catches every `version` that begins a line and stores version inside double quotes
find_pattern="^version = \".*\"$"
replace_pattern="s/${find_pattern}/version = \"${version}\"/"

get_current_version() {
  local current_version=""
  if [ "$(uname)" == "Darwin" ]; then
    # macOS
    current_version=$(grep -Eo "$find_pattern" "$file" | sed 's/^version = "//;s/"$//')
  else
    # Linux
    current_version="$(grep -oP '(?<=^version = ")[^"]+' "$file" | head -n 1)"
  fi

  echo "$current_version"
}

replace_version() {
  if [ "$(uname)" == "Darwin" ]; then
    # macOS
    sed -i '' "$replace_pattern" "$file"
  else
    # Linux
    sed -i "$replace_pattern" "$file"
  fi
}

find_and_replace() {
  local crate=$1
  local file="Cargo.toml"

  if grep -q "$find_pattern" "$file"; then
    local prev_version=$(get_current_version)
    replace_version
    local new_version=$(get_current_version)
    echo -e "${CYAN} Successfully changed the version inside $file for ${crate#./} (v$prev_version -> v$new_version)${NC}"
  else
    echo -e "${RED} Error: Failed to change the version inside $file for ${crate#./}${NC}"
    final_exit_code=1
    grep_failures+=("$crate")
    return 1
  fi
}

update_lockfile() {
  local crate=$1
  local file="Cargo.lock"

  if cargo update --workspace; then
    echo -e "${CYAN} Successfully updated $file for ${crate#./}${NC}"
  else
    echo -e "${RED} Error: Failed to update $file for ${crate#./}${NC}"
    final_exit_code=1
    lockfile_failures+=("$crate")
    return 1
  fi
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

if [[ $final_exit_code != 0 ]]; then
  [[ "${#grep_failures[@]}" != "0" ]] && echo -e "${RED} Error: Failed to find 'version' for ${#grep_failures[@]} crate(s): ${grep_failures[*]}"
  [[ "${#lockfile_failures[@]}" != "0" ]] && echo -e "${RED} Error: Failed to generate lockfile for ${#lockfile_failures[@]} crate(s): ${lockfile_failures[*]}"
else
  echo -e "${GREEN} The version number has been updated to $version."
fi

exit $final_exit_code
