# First stage of multi-stage build: build the Go binary
FROM golang:alpine AS builder

# Create directory for build context
WORKDIR /build

# Copy everything inside the container
COPY . .

# Download all dependencies
RUN go mod download

# Build the Go app
RUN CGO_ENABLED=0 go build -ldflags="-X main.AppVersion=$(cat VERSION) -s -w" -trimpath -o subsnipe .

# Second stage of multi-stage build: run the Go binary
FROM alpine:latest

# An env variable because e.g. the output directory needs to be different when the tool runs in docker
ENV RUNNING_ENVIRONMENT=docker

WORKDIR /app

# Create the directory for the output.md file
RUN mkdir output 

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /build/subsnipe /app/subsnipe

# Copy the fingerprint files from the previous stage
COPY --from=builder /build/fingerprints /app/fingerprints

# Run the executable
ENTRYPOINT ["/app/subsnipe"]