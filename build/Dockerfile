# syntax=docker/dockerfile:1.7

FROM golang:1.25.1-alpine AS base
WORKDIR /app

# Copy dependency files first for better caching
COPY go.mod go.sum ./

# Download dependencies with cache mount for faster builds
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Copy source code
COPY . .

# This target is for development - simple build and run
FROM base AS dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o iam ./cmd/api
EXPOSE 8080
CMD ["./iam"]

# This target is for production builds
FROM base AS builder
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o iam ./cmd/api

FROM gcr.io/distroless/base-debian12 AS final
WORKDIR /app

COPY --from=builder /app/iam ./iam
COPY migrations ./migrations
COPY gen ./gen

ENV APP_PORT=8080
EXPOSE 8080

ENTRYPOINT ["/app/iam"]
