#!/bin/bash

set -e

# Configuration
TARGET_DIR="ip_country/src"
DB_FILENAME="dbip.mmdb"
DOWNLOAD_PAGE="https://db-ip.com/db/download/ip-to-country-lite"
TEMP_DIR=$(mktemp -d)

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --output-dir)
            TARGET_DIR="$2"
            shift 2
            ;;
        --filename)
            DB_FILENAME="$2"
            shift 2
            ;;
        --force)
            FORCE_DOWNLOAD=1
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --output-dir DIR    Directory to store the database (default: ip_country/src)"
            echo "  --filename NAME     Name of the output file (default: dbip.mmdb)"
            echo "  --force            Force download even if file exists"
            echo "  --help             Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Ensure cleanup on script exit
cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Check if curl is available
if ! command -v curl >/dev/null 2>&1; then
    echo "Error: curl is not installed"
    exit 1
fi

# Check if target file already exists
TARGET_PATH="$TARGET_DIR/$DB_FILENAME"
if [ -f "$TARGET_PATH" ] && [ -z "$FORCE_DOWNLOAD" ]; then
    echo "Database file already exists at $TARGET_PATH"
    echo "Use --force to download anyway"
    exit 0
fi

echo "Fetching download page..."
# Fetch the download page and extract the latest download link
DOWNLOAD_URL=$(curl -s "$DOWNLOAD_PAGE" | grep -oP 'https://download\.db-ip\.com/free/dbip-country-lite-\d{4}-\d{2}\.mmdb\.gz' | head -1)

# Check if we found a URL
if [ -z "$DOWNLOAD_URL" ]; then
    echo "Error: Failed to find the download link on the page"
    exit 1
fi

# Extract date from URL for version checking
DB_DATE=$(echo "$DOWNLOAD_URL" | grep -oP '\d{4}-\d{2}')
echo "Found database version: $DB_DATE"

# Create target directory if it doesn't exist
mkdir -p "$TARGET_DIR"

# Download the latest dbip IP-to-country data with progress bar
echo "Downloading database from $DOWNLOAD_URL..."
if ! curl -L --progress-bar -o "$TEMP_DIR/dbip.mmdb.gz" "$DOWNLOAD_URL"; then
    echo "Error: Download failed"
    exit 1
fi

# Verify downloaded file
if [ ! -s "$TEMP_DIR/dbip.mmdb.gz" ]; then
    echo "Error: Downloaded file is empty"
    exit 1
fi

# Extract the data
echo "Extracting database..."
if ! gunzip -f "$TEMP_DIR/dbip.mmdb.gz"; then
    echo "Error: Failed to extract the database"
    exit 1
fi

# Verify the extracted file
if [ ! -s "$TEMP_DIR/dbip.mmdb" ]; then
    echo "Error: Extracted database is empty"
    exit 1
fi

# Basic format verification (check for MaxMind DB format magic bytes)
if ! head -c4 "$TEMP_DIR/dbip.mmdb" | grep -q "MaxMind.com"; then
    echo "Error: Downloaded file does not appear to be a valid MaxMind DB"
    exit 1
fi

# Backup existing file if it exists
if [ -f "$TARGET_PATH" ]; then
    echo "Backing up existing database to ${TARGET_PATH}.bak"
    cp "$TARGET_PATH" "${TARGET_PATH}.bak"
fi

# Move the extracted file to the target directory
echo "Moving database to $TARGET_PATH..."
if ! mv "$TEMP_DIR/dbip.mmdb" "$TARGET_PATH"; then
    echo "Error: Failed to move database to target location"
    # Restore backup if it exists
    if [ -f "${TARGET_PATH}.bak" ]; then
        mv "${TARGET_PATH}.bak" "$TARGET_PATH"
    fi
    exit 1
fi

# Remove backup if move was successful
rm -f "${TARGET_PATH}.bak"

echo "Successfully downloaded and installed database version $DB_DATE to $TARGET_PATH"
echo "You can now run generate_dbip_country.sh to update the Rust code"
