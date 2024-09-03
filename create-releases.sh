#!/usr/bin/env sh

FLAGS="-s -w"

rm -rf releases
mkdir -p releases

# build for Windows
GOOS=windows GOARCH=amd64 go build -ldflags="$FLAGS" -trimpath
mv subsnipe.exe releases/subsnipe-windows-amd64.exe

# build for M1 Macs (arm64)
GOOS=darwin GOARCH=arm64 go build -ldflags="$FLAGS" -trimpath
mv subsnipe releases/subsnipe-mac-arm64

# build for Intel Macs (amd64)
GOOS=darwin GOARCH=amd64 go build -ldflags="$FLAGS" -trimpath
mv subsnipe releases/subsnipe-mac-amd64

# build for x64 Linux (amd64)
GOOS=linux GOARCH=amd64 go build -ldflags="$FLAGS" -trimpath
mv subsnipe releases/subsnipe-linux-amd64