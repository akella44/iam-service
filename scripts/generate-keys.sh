#!/bin/bash

# Script to generate RSA key pair for JWT signing
# Usage: ./scripts/generate-keys.sh [output_dir]

set -e

OUTPUT_DIR="${1:-./build/compose/secrets}"

mkdir -p "$OUTPUT_DIR"

echo "Generating RSA key pair in $OUTPUT_DIR..."

# Generate private key (2048 bits)
openssl genrsa -out "$OUTPUT_DIR/private.pem" 2048

# Extract public key from private key
openssl rsa -in "$OUTPUT_DIR/private.pem" -pubout -outform PEM -out "$OUTPUT_DIR/public.pem"

# Set proper permissions
chmod 600 "$OUTPUT_DIR/private.pem"
chmod 644 "$OUTPUT_DIR/public.pem"

echo "Keys generated successfully:"
echo "  Private key: $OUTPUT_DIR/private.pem"
echo "  Public key:  $OUTPUT_DIR/public.pem"
