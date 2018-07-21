#!/bin/sh

set -eu

OFTR_VERSION="0.50.0"

OFTR_APK_NAME="oftr-${OFTR_VERSION}-r0.apk"
OFTR_APK_URL="https://github.com/byllyfish/alpine-oftr/releases/download/$OFTR_VERSION"

# Raspberry Pi version of apk has "-pi" appended to URL root.
if [ `uname -m` = "armv7l" ]; then
    OFTR_APK_URL="${OFTR_APK_URL}-pi"
fi

# Install oftr package manually. Does NOT check code signature because package
# is currently generated with disposable public/private key.

wget "$OFTR_APK_URL/$OFTR_APK_NAME"
apk add --allow-untrusted "$OFTR_APK_NAME"
rm "$OFTR_APK_NAME"
