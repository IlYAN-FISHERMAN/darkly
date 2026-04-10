#!/bin/bash

BASE_URL="http://10.11.10.2:8443/.hidden"
OUTPUT_FILE="readme_contents.txt"
 
> "$OUTPUT_FILE"
 
crawl() {
    local url="$1"
 
    # Fetch the index page with timeouts
    local page
    page=$(curl -s --connect-timeout 3 --max-time 5 "$url/")
    [ -z "$page" ] && return
 
    local subdirs
    subdirs=$(echo "$page" | grep -oP '(?<=href=")[a-z]+(?=/")' )
 
    # Check for a README in this directory
    local readme
    readme=$(curl -s --connect-timeout 3 --max-time 5 --fail "$url/README")
    if [ $? -eq 0 ] && [ -n "$readme" ]; then
        echo "=== $url/README ===" >> "$OUTPUT_FILE"
        echo "$readme" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        echo "[+] Found README at $url" >&2
    fi
 
    # Recurse into subdirectories
    for dir in $subdirs; do
        crawl "$url/$dir"
    done
}
 
echo "Starting crawl of $BASE_URL ..."
crawl "$BASE_URL"
echo "Done! Results saved to $OUTPUT_FILE"
