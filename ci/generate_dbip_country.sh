#!/bin/bash

set -e

DB_PATH="node/src/dbip.mmdb"
OUTPUT_PATH="node/src/dbip_country.rs"

# Initialize the output file with the header comment and the start of the array declaration
echo "// This file is generated automatically. Do not edit." > $OUTPUT_PATH
echo "" >> $OUTPUT_PATH
echo "pub const IP_COUNTRY_DATA: &[(&str, &str)] = &[" >> $OUTPUT_PATH

# Iterate over each network and extract the country ISO code
mmdblookup --file $DB_PATH --dump | grep -E 'network|iso_code' | while read -r line; do
    if [[ $line == *"network"* ]]; then
        network=$(echo $line | awk '{print $2}' | tr -d '"')
    elif [[ $line == *"iso_code"* ]]; then
        iso_code=$(echo $line | awk '{print $2}' | tr -d '"')
        echo "    (\"$network\", \"$iso_code\")," >> $OUTPUT_PATH
    fi
done

# Close the array declaration
echo "];" >> $OUTPUT_PATH

echo "File $OUTPUT_PATH has been generated."
