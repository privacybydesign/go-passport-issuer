#!/bin/bash

# Directory to scan (default to current if not given)
INPUT_DIR="${1:-.}"

# Output directory (optional)
OUTPUT_DIR="${2:-$INPUT_DIR/converted}"
mkdir -p "$OUTPUT_DIR"

# Loop over all .der files in the directory
for der_file in "$INPUT_DIR"/*.der; do
    if [[ ! -f "$der_file" ]]; then
        echo "No .der files found in $INPUT_DIR"
        continue
    fi

    # Convert DER to temporary PEM
    temp_pem=$(mktemp)
    openssl x509 -in "$der_file" -inform DER -out "$temp_pem" -outform PEM

    # Extract the subject line
    subject=$(openssl x509 -in "$der_file" -inform DER -noout -subject)

    # Extract and normalize the country code (case-insensitive match, then uppercase)
    country=$(echo "$subject" | sed -n 's/.*[Cc] *= *\([A-Za-z][A-Za-z]\).*/\1/p' | tr '[:lower:]' '[:upper:]')

    # Fallback if country not found
    if [[ -z "$country" ]]; then
        country="UNKNOWN"
    fi

    # Create output filename
    base_name=$(basename "$der_file" .der)
    output_file="$OUTPUT_DIR/${country}_${base_name}.cer"

    # Final conversion
    openssl x509 -in "$der_file" -inform DER -out "$output_file" -outform PEM

    echo "Converted $der_file -> $output_file"

    # Cleanup
    rm "$temp_pem"
done
