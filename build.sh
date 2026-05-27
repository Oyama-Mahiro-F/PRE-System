#!/bin/bash
SRC_DIR="src"
OUT_DIR="out"

mkdir -p "$OUT_DIR"

echo "================================================================"
echo "  Compiling PRE System..."
echo "================================================================"
javac -encoding UTF-8 -d "$OUT_DIR" \
    "$SRC_DIR/crypto/pre/PREInterface.java" \
    "$SRC_DIR/crypto/rsa/RSAKeyPair.java" \
    "$SRC_DIR/crypto/ecc/ECCKeyPair.java" \
    "$SRC_DIR/crypto/pre/RSAPRE.java" \
    "$SRC_DIR/crypto/pre/ECCPRE.java" \
    "$SRC_DIR/proxy/ProxyServer.java" \
    "$SRC_DIR/scenario/DataSharingDemo.java" \
    "$SRC_DIR/Main.java"

if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit 1
fi

echo ""
echo "================================================================"
echo "  Running PRE System Demo..."
echo "================================================================"
echo ""
java -Dfile.encoding=UTF-8 -cp "$OUT_DIR" Main
