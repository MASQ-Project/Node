#!/bin/bash -xev
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
STATUS=$1

case "$OSTYPE" in
  msys)
    GENERATED_TYPE="windows"
    ;;
  Darwin | darwin*)
    GENERATED_TYPE="mac"
    ;;
  linux*)
    GENERATED_TYPE="linux"
    ;;
  *)
    GENERATED_TYPE="unknown"
    ;;
esac
if [[ "$PUBLISH_TOKEN" == "" ]]; then
  echo "No PUBLISH_TOKEN set; can't publish results"
  exit 0
fi

if [[ "$RESULTS_REPO_OWNER" == "" ]]; then
  echo "No RESULTS_REPO_OWNER set; can't publish results"
  exit 0
fi

if [[ "$RESULTS_REPO_NAME" == "" ]]; then
  echo "No RESULTS_REPO_NAME set; can't publish results"
  exit 0
fi

git status
RESULTS_LABEL="$GITHUB_HEAD_REF"
GENERATED_NAME="generated-$GENERATED_TYPE"

pushd "$CI_DIR/../results"
rm -rf repo || echo "No leftover repo to delete"
git clone "https://$RESULTS_REPO_OWNER:$PUBLISH_TOKEN@github.com/$RESULTS_REPO_OWNER/$RESULTS_REPO_NAME.git" repo
cd repo
cp README.md README.md.old
NEW_LINE="* $(date -u) - $RESULTS_LABEL ($GENERATED_TYPE) - $STATUS: [$GENERATED_NAME.tar.gz](https://github.com/$RESULTS_REPO_OWNER/$RESULTS_REPO_NAME/blob/master/results/$RESULTS_LABEL/$GENERATED_NAME.tar.gz?raw=true)"
cat README.md.old | grep -v "$RESULTS_LABEL ($GENERATED_TYPE)" > README.md.clean
cat README.md.clean | sed -e '/\(Results Marker\)/q' > README.md
echo "$NEW_LINE" >> README.md
cat README.md.clean | sed -n '/\(Results Marker\)/,$p' | tail -n+2 >> README.md

mkdir -p "results/$RESULTS_LABEL"
cp ../generated.tar.gz "results/$RESULTS_LABEL/$GENERATED_NAME.tar.gz"
git config user.email "developers@masq.ai"
git config user.name "MASQ"
git checkout --orphan new-master
git add README.md results
git commit -m "Latest results for $RESULTS_LABEL ($GENERATED_TYPE) - $STATUS"
git branch -D master
git branch -M new-master master
git checkout master
git push -f -u origin HEAD

popd
