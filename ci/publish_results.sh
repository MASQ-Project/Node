#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
STATUS=$1

pushd "$CI_DIR/../results"
rm -rf repo || echo "No leftover repo to delete"
git clone "https://substratum-temporary:$GITHUB_TOKEN@github.com/substratum-temporary/SubstratumNode-results.git" repo
cd repo
cp README.md README.md.old
if [[ "$TRAVIS_PULL_REQUEST_SLUG" == "" ]]; then
  RESULTS_LABEL="$TRAVIS_BRANCH"
else
  RESULTS_LABEL="$TRAVIS_PULL_REQUEST_SLUG"
fi
NEW_LINE="* $(date -u) - $RESULTS_LABEL - $STATUS: [generated.zip](https://github.com/substratum-temporary/SubstratumNode-results/blob/master/results/$RESULTS_LABEL/generated.zip?raw=true)"
cat README.md.old | grep -v "$RESULTS_LABEL" > README.md.clean
cat README.md.clean | sed -e '/\(Results Marker\)/q' > README.md
echo "$NEW_LINE" >> README.md
cat README.md.clean | sed -n '/\(Results Marker\)/,$p' | tail -n+2 >> README.md

mkdir -p "results/$RESULTS_LABEL"
cp ../generated.zip "results/$RESULTS_LABEL/generated.zip"
git add README.md "results/$RESULTS_LABEL/generated.zip"
git commit -m "Latest results for $RESULTS_LABEL"
git push

popd
