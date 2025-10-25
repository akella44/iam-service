#!/usr/bin/env bash

# Script to generate RSA key pair for JWT signing with key identifiers (kid)
# Usage: ./scripts/generate-keys.sh [--kid kid-value] [--output-dir path] [--force]
# Legacy positional argument for output directory remains supported.

set -euo pipefail

DEFAULT_OUTPUT_DIR="./build/compose/secrets"
KID="v1"
OUTPUT_DIR=""
LEGACY_OUTPUT=""
FORCE=false

usage() {
	cat <<'EOF'
Usage: ./scripts/generate-keys.sh [options] [output_dir]

Options:
	--kid <value>          Key identifier (kid) used in generated file names (default: v1)
	--output-dir <path>    Directory to write key files (default: ./build/compose/secrets)
	--force                Overwrite existing key files if they exist
	-h, --help             Show this help message and exit

Examples:
	./scripts/generate-keys.sh
	./scripts/generate-keys.sh --kid key-2025-10-12
	./scripts/generate-keys.sh --kid v2 ./build/compose/secrets
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--kid)
			[[ $# -lt 2 ]] && { echo "error: --kid requires a value" >&2; usage; exit 1; }
			KID="$2"
			shift 2
			;;
		--kid=*)
			KID="${1#*=}"
			shift
			;;
		--output-dir|-o)
			[[ $# -lt 2 ]] && { echo "error: --output-dir requires a value" >&2; usage; exit 1; }
			OUTPUT_DIR="$2"
			shift 2
			;;
		--output-dir=*)
			OUTPUT_DIR="${1#*=}"
			shift
			;;
		--force)
			FORCE=true
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		--)
			shift
			break
			;;
		-*)
			echo "error: unknown option $1" >&2
			usage
			exit 1
			;;
		*)
			if [[ -z "$LEGACY_OUTPUT" ]]; then
				LEGACY_OUTPUT="$1"
				shift
			else
				echo "error: unexpected argument $1" >&2
				usage
				exit 1
			fi
			;;
	esac
done

if [[ -z "$OUTPUT_DIR" ]]; then
	OUTPUT_DIR="${LEGACY_OUTPUT:-$DEFAULT_OUTPUT_DIR}"
elif [[ -n "$LEGACY_OUTPUT" && "$OUTPUT_DIR" != "$LEGACY_OUTPUT" ]]; then
	echo "warning: conflicting output directory arguments; using $OUTPUT_DIR" >&2
fi

if [[ -z "$KID" ]]; then
	echo "error: kid must not be empty" >&2
	exit 1
fi

if [[ "$KID" =~ [[:space:]] ]]; then
	echo "error: kid must not contain whitespace" >&2
	exit 1
fi

if [[ ! "$KID" =~ ^[A-Za-z0-9._-]+$ ]]; then
	echo "error: kid must contain only alphanumeric characters, dots, underscores, or hyphens" >&2
	exit 1
fi

mkdir -p "$OUTPUT_DIR"

PRIVATE_KEY_PATH="$OUTPUT_DIR/$KID.pem"
PUBLIC_KEY_PATH="$OUTPUT_DIR/$KID.pub.pem"

if ! $FORCE; then
	if [[ -e "$PRIVATE_KEY_PATH" || -e "$PUBLIC_KEY_PATH" ]]; then
		echo "error: key files for kid '$KID' already exist in $OUTPUT_DIR (use --force to overwrite)" >&2
		exit 1
	fi
fi

echo "Generating RSA key pair (kid=$KID) in $OUTPUT_DIR..."

# Generate private key (4096 bits for stronger security)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$PRIVATE_KEY_PATH"

# Extract public key from private key
openssl rsa -in "$PRIVATE_KEY_PATH" -pubout -outform PEM -out "$PUBLIC_KEY_PATH"

# Set proper permissions
chmod 600 "$PRIVATE_KEY_PATH"
chmod 644 "$PUBLIC_KEY_PATH"

# Maintain legacy symlinks for tooling expecting private.pem/public.pem
ln -sf "$(basename "$PRIVATE_KEY_PATH")" "$OUTPUT_DIR/private.pem"
ln -sf "$(basename "$PUBLIC_KEY_PATH")" "$OUTPUT_DIR/public.pem"

echo "Keys generated successfully:"
echo "  Private key: $PRIVATE_KEY_PATH"
echo "  Public key:  $PUBLIC_KEY_PATH"
echo "  Symlink     : $OUTPUT_DIR/private.pem -> $(basename "$PRIVATE_KEY_PATH")"
echo "  Symlink     : $OUTPUT_DIR/public.pem -> $(basename "$PUBLIC_KEY_PATH")"

echo
echo "Remember to update JWT_ACTIVE_KID environment variable to '$KID' where applicable."

