#!/bin/sh

set -eu

OFTR_VERSION="0.53.0"

OFTR_APK_NAME="oftr-${OFTR_VERSION}-r0.apk"
OFTR_APK_URL="https://github.com/byllyfish/alpine-oftr/releases/download/$OFTR_VERSION"
OFTR_APK_KEY="/etc/apk/keys/oftr-5b74d058.rsa.pub"

# Raspberry Pi version of apk has "-pi" appended to URL root.
if [ `uname -m` = "armv7l" ]; then
    OFTR_APK_URL="${OFTR_APK_URL}-pi"
fi

# Add public key (https://github.com/byllyfish/alpine-oftr/blob/master/oftr-5b74d058.rsa.pub)
cat > "$OFTR_APK_KEY" <<-EOF
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyoNITdNC44Tgqos1gN3u
LbW7jjPDrvdS/GtgV1xJbSGX9mzf+Mw4MBCxcj5o4zit/yjF4bkJX+TA6ScpVZEJ
io5unwYzEni86U+heiqJ3ZYMmZntupHi2VLjDQ69b7xADijtxL7lNzPq+kKi1xQv
aG9rceZp7WN4WzZnSwlGuTB1nUiyEV5V3WuI7DvlzLZEOURSOShHo7QjcxaKirw+
oFyLK2vVhfUAcsaIWidjrHQO84kopdBOFNuoxfsPu53aEzcqIxiCFsl3L/5+41uK
pOCBH8UAMYm1NuQ438KUxLNltN7OgwT7HNrl55fI0Tn1H11JvSQ24pfuJqPWfXin
5QIDAQAB
-----END PUBLIC KEY-----
EOF

# Install oftr package manually.
wget "$OFTR_APK_URL/$OFTR_APK_NAME"
apk add "$OFTR_APK_NAME"

rm "$OFTR_APK_NAME"
rm "$OFTR_APK_KEY"
