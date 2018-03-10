#!/bin/bash

set -e

MACOS_BIN_NAME=dns-bin
MACOS_APP_NAME=SubstratumDNS
MACOS_APP_DIR=target/dist/$MACOS_APP_NAME.app

echo "Creating app directory structure"
rm -rf $MACOS_APP_DIR
mkdir -p $MACOS_APP_DIR/Contents/MacOS

echo "Copying frameworks"
cp -r $MACOS_FRAMEWORKS $MACOS_APP_DIR/Contents

cargo rustc \
    --verbose \
    --release \
    --features use_sdl2_mac_framework \
    -- \
    -Clink-args="-Wl,-F,$MACOS_FRAMEWORKS"

echo "Copying binary"
MACOS_APP_BIN=$MACOS_APP_DIR/Contents/MacOS/$MACOS_BIN_NAME
cp target/release/$APP_NAME $MACOS_APP_BIN

echo "Linking binary with frameworks"
for old in `otool -L $MACOS_APP_BIN | grep @rpath | cut -f2 | cut -d' ' -f1`; do
    new=`echo $old | sed -e "s/@rpath/@executable_path\/..\/Frameworks/"`
    echo "Replacing '$old' with '$new'"
    install_name_tool -change $old $new $MACOS_APP_BIN
done

echo "Copying resources directory"
cp -r $RESOURCES $MACOS_APP_DIR/Contents/MacOS
echo "Copying user directory"
cp -r $USER $MACOS_APP_DIR/Contents/MacOS

$MACOS_APP_BIN --help

echo "Copying launcher"
cp scripts/macos_launch.sh $MACOS_APP_DIR/Contents/MacOS/$MACOS_APP_NAME

echo "Creating dmg"
mkdir $MACOS_APP_NAME
mv $MACOS_APP_DIR $MACOS_APP_NAME
ln -s /Applications $MACOS_APP_NAME/Applications
rm -rf $MACOS_APP_NAME/.Trashes

FULL_NAME=$APP_NAME-$OS-$MACHINE-$SUFFIX

hdiutil create uploads/$FULL_NAME.dmg -srcfolder $MACOS_APP_NAME -ov
rm -rf $MACOS_APP_NAME
