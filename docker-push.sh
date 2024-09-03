#!/usr/bin/env sh

# Get the current version of the tool from `./VERSION`
VERSION=$(cat VERSION)

# Create a new Buildx builder with docker-container driver
BUILDER_NAME=mybuilder

# Remove any existing builder with the same name
docker buildx rm $BUILDER_NAME 2>/dev/null || true

# Create a new builder
docker buildx create --name $BUILDER_NAME --driver docker-container --use

# Build and push the Docker image
docker buildx build --platform linux/amd64,linux/arm64 --push . -t fw10/subsnipe:$VERSION -t fw10/subsnipe:latest
