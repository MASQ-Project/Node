#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
function sudo_ask() {
  case "$OSTYPE" in
    msys)
      "$@"
      ;;
    Darwin | darwin* | linux*)
      sudo "$@"
      ;;
  esac
}

function node_ui_logs_specific() {
    LOCAL="$1"
    LOGS_DIR="$2"
    sudo_ask mkdir -p "generated/node-ui/$LOCAL/Substratum"
    sudo_ask cp -R "$HOME/$LOCAL/Substratum" "generated/node-ui/$LOCAL/Substratum" || echo "No logs from SubstratumNode"

    if [[ "$LOGS_DIR" != "" ]]; then
      sudo_ask mkdir -p "generated/node-ui/$LOGS_DIR/SubstratumNode"
      sudo_ask mkdir -p "generated/node-ui/$LOGS_DIR/Electron"
      sudo_ask cp -R "$HOME/$LOGS_DIR/SubstratumNode/logs" "generated/node-ui/$LOGS_DIR/SubstratumNode" || echo "No Electron SubstratumNode logs"
      sudo_ask cp "$HOME/$LOGS_DIR/SubstratumNode/log.log" "generated/node-ui/$LOGS_DIR/SubstratumNode" || echo "No Electron SubstratumNode log"
      sudo_ask cp -R "$HOME/$LOGS_DIR/Electron/logs" "generated/node-ui/$LOGS_DIR/Electron" || echo "No Electron logs"
      sudo_ask cp -R "$HOME/$LOGS_DIR/jasmine" "generated/node-ui/$LOGS_DIR/jasmine" || echo "No jasmine logs"
    fi
}

function node_ui_logs_generic() {
    case "$OSTYPE" in
      msys)
        node_ui_logs_specific "AppData/Local" "AppData/Roaming"
        ;;
      Darwin | darwin*)
        node_ui_logs_specific "Library/Application Support" "Library/Logs"
        ;;
      linux*)
        node_ui_logs_specific ".local/share" ".config"
        ;;
      *)
        echo "Unrecognized operating system $OSTYPE"
        exit 1
        ;;
    esac
}

mkdir -p "$CI_DIR/../results"
pushd "$CI_DIR/../results"
sudo_ask rm -rf generated
mkdir generated
sudo_ask cp -R ../node/generated generated/node || echo "No results from SubstratumNode"
cp -R ../dns_utility/generated generated/dns_utility || echo "No results from dns_utility"
cp -R ../multinode_integration_tests/generated generated/multinode_integration_tests || echo "No results from multinode integration tests"
sudo_ask cp -R ../node-ui/generated generated/node-ui || echo "No results from SubstratumNode UI"
cp -R ../node-ui/dist generated/dist || echo "No distributable binaries"
node_ui_logs_generic
sudo_ask tar -czvf generated.tar.gz generated/*
popd
