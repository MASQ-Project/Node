#!/bin/bash -ev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

if [[ "$1" == "" ]]; then
  CACHE_TARGET="$HOME"
else
  CACHE_TARGET="$1"
fi

if [[ "$2" == "" ]]; then
  NODE_VERSION="10.16.3"
else
  NODE_VERSION="$2"
fi

function install_linux() {
  rm -r "$HOME/.nvm" || echo "node.js not installed"
  curl -sL https://deb.nodesource.com/setup_10.x | sudo bash -
  sudo apt-get update
  sudo apt-get install -y nodejs
  source "$HOME/.nvm/nvm.sh"
  nvm install "$NODE_VERSION"

  mkdir -p "$CACHE_TARGET/usr/bin"
  cp "/usr/bin/node" "$CACHE_TARGET/usr/bin/node"
  cp -R "$HOME/.nvm" "$CACHE_TARGET/.nvm"

  rm -r "$HOME/.yarn" || echo "yarn not installed"
  curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
  echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
  sudo apt-get update
  sudo apt-get install -y yarn

  cp -R "$HOME/.yarn" "$CACHE_TARGET/.yarn"
}

function install_macOS() {
  rm -r "$HOME/.nvm" || echo "node.js not installed"
  brew install node || echo "node.js is already installed"
  source "$HOME/.nvm/nvm.sh"
  nvm install "$NODE_VERSION"

  cp -R "$HOME/.nvm" "$CACHE_TARGET/.nvm"

  rm -r "$HOME/.yarn" || echo "yarn not installed"
  npm install -g yarn

  cp -R "$HOME/.yarn" "$CACHE_TARGET/.yarn"
}

function install_windows() {
  CACHE_TARGET=$(echo $CACHE_TARGET | sed 's|\\|/|g' | sed 's|^\([A-Za-z]\):|/\1|g')
  rm -r "$HOME/.nvm" || echo "node.js not installed"
  msiexec.exe //a "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-x64.msi" //quiet
  source "$HOME/.nvm/nvm.sh"
  nvm install "$NODE_VERSION"

  cp -R "$HOME/.nvm" "$CACHE_TARGET/.nvm"

  rm -r "$HOME/.yarn" || echo "yarn not installed"
  npm install -g yarn

  cp -R "$HOME/.yarn" "$CACHE_TARGET/.yarn"
}

case "$OSTYPE" in
  msys)
    install_windows
    ;;
  Darwin | darwin*)
    install_macOS
    ;;
  linux*)
    install_linux
    ;;
  *)
    echo "Unrecognized operating system $OSTYPE"
    exit 1
    ;;
esac
