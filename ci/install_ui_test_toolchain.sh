#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

function install_linux() {
  wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
  echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google.list
  sudo apt update
  sudo apt install -y google-chrome-stable xvfb
}

function install_macOS() {
  brew update
  brew install cask || echo "Cask already installed"
  brew cask install google-chrome || echo "Chrome already installed"
}

function install_windows() {
  # Unfortunately 'choco install googlechrome -y' fails on our Azure agent host.
  # So we get the latest Chrome with nothing but stone knives and bearskins!
   curl "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7BD3E0CE1F-2634-7AEB-D15F-82C77C14A52F%7D%26lang%3Den%26browser%3D3%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-stable-statsdef_1%26installdataindex%3Dempty/chrome/install/ChromeStandaloneSetup64.exe" > "$TEMP/ChromeStandaloneSetup.exe"
  cmd //C "echo.>%TEMP%\ChromeStandaloneSetup.exe:Zone.Identifier"
  "$TEMP/ChromeStandaloneSetup.exe" //silent //install
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
    exit 1
    ;;
esac
