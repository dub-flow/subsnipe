# First stage of multi-stage build: build the Go binary
FROM golang:alpine AS builder

# Install upx for compressing the binary and reducing the docker image size
RUN apk --no-cache add upx

# Create directory for build context
WORKDIR /build

# Copy everything inside the container
COPY go.mod .
COPY go.sum .
COPY *.go .
COPY VERSION .
COPY fingerprints ./fingerprints

# Download all dependencies
RUN go mod download

# Build the Go app. Set 'RUNNING_ENVIRONMENT' because e.g. the output directory needs to be different when the tool runs in docker
RUN CGO_ENABLED=0 go build -ldflags="-X main.RUNNING_ENVIRONMENT=docker -s -w" -trimpath -o subsnipe .

# Compress the binary using UPX
RUN upx --ultra-brute -qq subsnipe && upx -t subsnipe

# Second stage of multi-stage build: run the Go binary
FROM alpine:latest

# Create a new non-root user
RUN adduser -D -g '' appuser

# Install dig
# RUN apk --no-cache add bind-tools

WORKDIR /app

# Create the directory for the output.md file and set permissions
RUN mkdir output && chown -R appuser:appuser /app

# Copy the pre-built binary file from the previous stage
COPY --from=builder /build/subsnipe /app/subsnipe

# Copy the fingerprint files from the previous stage
COPY --from=builder /build/fingerprints /app/fingerprints

# Change ownership of the files to the new user
RUN chown -R appuser:appuser /app/subsnipe /app/fingerprints

# Switch to the non-root user
USER appuser

# Run the executable
ENTRYPOINT ["/app/subsnipe"]
