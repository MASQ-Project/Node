#!/bin/bash

set -e

# Configuration
DB_PATH="ip_country/src/dbip.mmdb"
OUTPUT_PATH="ip_country/src/dbip_country.rs"
BACKUP_SUFFIX=".bak"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --input)
            DB_PATH="$2"
            shift 2
            ;;
        --output)
            OUTPUT_PATH="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--input path/to/dbip.mmdb] [--output path/to/output.rs]"
            exit 1
            ;;
    esac
done

# Check for required commands
if ! command -v mmdblookup >/dev/null 2>&1; then
    echo "Error: mmdblookup command not found"
    echo "Please install libmaxminddb-tools package"
    exit 1
fi

# Check if the database file exists
if [ ! -f "$DB_PATH" ]; then
    echo "Error: Database file not found at $DB_PATH"
    echo "Please run the download_dbip.sh script first"
    exit 1
fi

# Ensure output directory exists
OUTPUT_DIR=$(dirname "$OUTPUT_PATH")
if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Creating output directory: $OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"
fi

# Backup existing file if it exists
if [ -f "$OUTPUT_PATH" ]; then
    echo "Backing up existing file to ${OUTPUT_PATH}${BACKUP_SUFFIX}"
    cp "$OUTPUT_PATH" "${OUTPUT_PATH}${BACKUP_SUFFIX}"
fi

# Initialize the output file
echo "Generating Rust code..."
cat > "$OUTPUT_PATH" << EOL
// This file is generated automatically. Do not edit.
// Generated from: $DB_PATH
// Generated on: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

pub const IP_COUNTRY_DATA: &[(&str, &str)] = &[
EOL

# Create a temporary file for the mmdb dump
TEMP_FILE=$(mktemp)
echo "Dumping database contents..."
mmdblookup --file "$DB_PATH" --dump > "$TEMP_FILE"

# Process the mmdb data
declare -A country_data
current_network=""
count=0

echo "Processing database entries..."
while IFS= read -r line; do
    if [[ $line =~ \"network\":[[:space:]]*\"([^\"]+)\" ]]; then
        current_network="${BASH_REMATCH[1]}"
    elif [[ $line =~ \"iso_code\":[[:space:]]*\"([^\"]+)\" ]] && [[ -n "$current_network" ]]; then
        iso_code="${BASH_REMATCH[1]}"
        echo "    (\"$current_network\", \"$iso_code\")," >> "$OUTPUT_PATH"
        current_network=""
        ((count++))
        if ((count % 1000 == 0)); then
            echo "Processed $count entries..."
        fi
    fi
done < "$TEMP_FILE"

# Clean up
rm -f "$TEMP_FILE"

# Close the array
echo "];" >> "$OUTPUT_PATH"

# Verify the generated file
if ! rustc --check "$OUTPUT_PATH" 2>/dev/null; then
    echo "Warning: Generated file may not be valid Rust code"
    echo "Restoring backup from ${OUTPUT_PATH}${BACKUP_SUFFIX}"
    mv "${OUTPUT_PATH}${BACKUP_SUFFIX}" "$OUTPUT_PATH"
    exit 1
fi

# Remove backup if verification passed
rm -f "${OUTPUT_PATH}${BACKUP_SUFFIX}"

echo "Successfully generated $OUTPUT_PATH with $count entries"
