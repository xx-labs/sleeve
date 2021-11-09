#!/bin/bash
echo "==> Building sleevage CLI for Mac"
GOOS=darwin GOARCH=amd64 go build -o bin/sleevage-mac
echo "==> Building sleevage CLI for Mac M1"
GOOS=darwin GOARCH=arm64 go build -o bin/sleevage-mac-m1
echo "==> Building sleevage CLI for Linux"
GOOS=linux GOARCH=amd64 go build -o bin/sleevage-linux
echo "==> Building sleevage CLI for ARM (64-bit) Linux"
GOOS=linux GOARCH=arm64 go build -o bin/sleevage-arm-linux
echo "==> Building sleevage CLI for ARM (32-bit) Linux"
GOOS=linux GOARCH=arm go build -o bin/sleevage-arm-32bit-linux
echo "==> Building sleevage CLI for Windows"
GOOS=windows GOARCH=amd64 go build -o bin/sleevage-windows.exe
shasum -a 256 bin/*
