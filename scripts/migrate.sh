#!/usr/bin/env bash
set -euo pipefail

: "${DB_HOST:=localhost}"
: "${DB_PORT:=5432}"
: "${DB_USER:=iam}"
: "${DB_PASSWORD:=iam_password}"
: "${DB_NAME:=iam}"
: "${DB_SSL_MODE:=disable}"

migrate -path migrations -database "postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=${DB_SSL_MODE}" "$@"
