#!/usr/bin/env sh

# get the current version of the tool from `./VERSION`
VERSION=$(cat VERSION)

docker buildx build --platform linux/amd64,linux/arm64 --push . -t fw10/subsnipe:$VERSION -t fw10/subsnipe:latest