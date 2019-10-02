#!/bin/bash -ev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

function check_variable() {
  if [[ "$1" == "" ]]; then
    echo "variable $2 required"
    exit 1
  fi
}
check_variable "$TAG_NAME" "TAG_NAME"
check_variable "$ARTIFACT_STAGING_DIR" "ARTIFACT_STAGING_DIR"
check_variable "$WORKSPACE" "WORKSPACE"

export ARTIFACT_STAGING_SUBDIR=$(echo "$ARTIFACT_STAGING_DIR/"*)
export DISTRIBUTE_STAGING_DIR="$WORKSPACE/s3-dist"

cd "$ARTIFACT_STAGING_SUBDIR"

mkdir -p "$DISTRIBUTE_STAGING_DIR"
cp -v SubstratumNode-macOS-binary.zip "$DISTRIBUTE_STAGING_DIR/SubstratumNode-${TAG_NAME}"-macOS-binary.zip
cp -v SubstratumNode-macOS.dmg.zip "$DISTRIBUTE_STAGING_DIR/SubstratumNode-${TAG_NAME}"-macOS.dmg.zip

cp -v SubstratumNode-Linux64-binary.zip "$DISTRIBUTE_STAGING_DIR/SubstratumNode-${TAG_NAME}"-Linux64-binary.zip
cp -v SubstratumNode-Linux64-deb.zip "$DISTRIBUTE_STAGING_DIR/SubstratumNode-${TAG_NAME}"-Linux64-deb.zip

cp -v SubstratumNode-Windows-binary.zip "$DISTRIBUTE_STAGING_DIR/SubstratumNode-${TAG_NAME}"-Windows-binary.zip
cp -v SubstratumNode-Windows.exe.zip "$DISTRIBUTE_STAGING_DIR/SubstratumNode-${TAG_NAME}"-Windows.exe.zip

cd "$DISTRIBUTE_STAGING_DIR"

for file in *.zip; do
    shasum -a 256 -b "$file" > "$file.sha"
done

if ! shasum -c "SubstratumNode-${TAG_NAME}-"*.sha; then
    echo "Problem found with SubstratumNode-${TAG_NAME}... distribution files"
    exit 1
fi
