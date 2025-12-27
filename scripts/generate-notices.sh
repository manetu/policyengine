#!/bin/bash
# Copyright Manetu Inc. All Rights Reserved.
#
# Generates a NOTICES file containing all third-party dependency licenses.
# Requires: go-licenses (go install github.com/google/go-licenses@latest)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_FILE="$PROJECT_ROOT/NOTICES"
TEMP_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

cd "$PROJECT_ROOT"

# Check for go-licenses
if ! command -v go-licenses &> /dev/null; then
    echo "Error: go-licenses not found. Install with: go install github.com/google/go-licenses@latest"
    exit 1
fi

echo "Generating NOTICES file..."

# Get license report as CSV
go-licenses report ./... 2>/dev/null > "$TEMP_DIR/licenses.csv"

# Save all license texts to temp directory
go-licenses save ./... --save_path="$TEMP_DIR/licenses" 2>/dev/null || true

# Generate the NOTICES file
cat > "$OUTPUT_FILE" << 'EOF'
THIRD-PARTY SOFTWARE NOTICES AND INFORMATION

This project incorporates components from the projects listed below. The original
copyright notices and license terms are set forth below. Manetu Inc. reserves all
rights not expressly granted herein, whether by implication, estoppel or otherwise.

================================================================================
EOF

# Parse the CSV and generate the dependency table
echo "" >> "$OUTPUT_FILE"
echo "DEPENDENCY LICENSES SUMMARY" >> "$OUTPUT_FILE"
echo "============================" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Create a formatted table
printf "%-60s %s\n" "Package" "License" >> "$OUTPUT_FILE"
printf "%-60s %s\n" "-------" "-------" >> "$OUTPUT_FILE"

# Sort and format the report (skip the project's own module)
grep -v "^github.com/manetu/policyengine," "$TEMP_DIR/licenses.csv" | \
    sort | \
    while IFS=, read -r pkg url license; do
        # Truncate long package names
        if [ ${#pkg} -gt 58 ]; then
            pkg="${pkg:0:55}..."
        fi
        printf "%-60s %s\n" "$pkg" "$license"
    done >> "$OUTPUT_FILE"

echo "" >> "$OUTPUT_FILE"
echo "=================================================================================" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "FULL LICENSE TEXTS" >> "$OUTPUT_FILE"
echo "==================" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Append full license texts
grep -v "^github.com/manetu/policyengine," "$TEMP_DIR/licenses.csv" | \
    sort | \
    while IFS=, read -r pkg url license; do
        LICENSE_DIR="$TEMP_DIR/licenses/$pkg"
        if [ -d "$LICENSE_DIR" ]; then
            LICENSE_FILE=$(find "$LICENSE_DIR" -type f \( -iname 'LICENSE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' \) 2>/dev/null | head -1)
            if [ -n "$LICENSE_FILE" ] && [ -f "$LICENSE_FILE" ]; then
                echo "--------------------------------------------------------------------------------" >> "$OUTPUT_FILE"
                echo "$pkg" >> "$OUTPUT_FILE"
                echo "License: $license" >> "$OUTPUT_FILE"
                echo "--------------------------------------------------------------------------------" >> "$OUTPUT_FILE"
                echo "" >> "$OUTPUT_FILE"
                cat "$LICENSE_FILE" >> "$OUTPUT_FILE"
                echo "" >> "$OUTPUT_FILE"
                echo "" >> "$OUTPUT_FILE"
            fi
        fi
    done

echo "NOTICES file generated at $OUTPUT_FILE"
