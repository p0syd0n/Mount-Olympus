#!/bin/bash

# Define HTML file path
HTML_FILE="public/views/create_account.ejs"

# Function to update integrity hash for a given JavaScript file
update_integrity() {
    local JS_FILE=$1
    local SCRIPT_NAME=$(basename "$JS_FILE")

    # Generate the SHA-384 hash and encode it in Base64
    HASH="sha384-"$(openssl dgst -sha384 -binary "$JS_FILE" | openssl base64 -A)

    # Escape special characters
    HASH_ESCAPED=$(echo "$HASH" | sed -e 's/[\/&]/\\&/g')

    # Use sed to replace the integrity attribute for the specific script
    sed -i "/$SCRIPT_NAME/ s/integrity=\"[^\"]*\"/integrity=\"$HASH_ESCAPED\"/" "$HTML_FILE"

    echo "Updated integrity hash for $SCRIPT_NAME in $HTML_FILE to $HASH_ESCAPED"
}

# Update both scripts
update_integrity "public/scripts/generate_keypair.js"
update_integrity "public/scripts/save_private_key_to_localstorage.js"
