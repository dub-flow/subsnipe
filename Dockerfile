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

WORKDIR /app

# Running as a non-root user
RUN adduser -D local
USER local

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /build/subsnipe /app/subsnipe

# Run the executable
ENTRYPOINT ["/app/subsnipe"]