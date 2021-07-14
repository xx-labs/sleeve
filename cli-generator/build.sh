#!/bin/bash
echo "==> Building Sleeve CLI for Mac"
GOOS=darwin GOARCH=amd64 go build -o bin/sleeve-mac
echo "==> Building Sleeve CLI for Mac M1"
GOOS=darwin GOARCH=arm64 go build -o bin/sleeve-mac-m1
echo "==> Building Sleeve CLI for Linux"
GOOS=linux GOARCH=amd64 go build -o bin/sleeve-linux
echo "==> Building Sleeve CLI for Windows"
GOOS=windows GOARCH=amd64 go build -o bin/sleeve-windows.exe
