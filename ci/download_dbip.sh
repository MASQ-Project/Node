#!/bin/bash

set -e

# Fetch the download page and extract the latest download link
DOWNLOAD_PAGE="https://db-ip.com/db/download/ip-to-country-lite"
DOWNLOAD_URL=$(curl -s $DOWNLOAD_PAGE | grep -oP 'https://download\.db-ip\.com/free/dbip-country-lite-\d{4}-\d{2}\.mmdb\.gz' | head -1)

# Check if we found a URL
if [ -z "$DOWNLOAD_URL" ]; then
  echo "Failed to find the download link on the page."
  exit 1
fi

# Download the latest dbip IP-to-country data
curl -o dbip-country-lite.mmdb.gz $DOWNLOAD_URL

# Extract the data
gunzip -f dbip-country-lite.mmdb.gz

# Cleanup: Remove temporary mmdb.gz file
rm dbip-country-lite.mmdb.gz

# Move the extracted file to the src directory
mv dbip-country-lite.mmdb node/src/dbip.mmdb
