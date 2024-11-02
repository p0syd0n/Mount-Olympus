#!/bin/bash

# Define paths to your files
JS_FILE="public/scripts/chatroom.js"
HTML_FILE="public/views/chatroom.ejs" # Change this to the path of your HTML file

# Generate the SHA-384 hash and encode it in Base64
HASH="sha384-"$(openssl dgst -sha384 -binary "$JS_FILE" | openssl base64 -A)

# Escape any special characters in the hash (in case you expand this for other commands)
HASH_ESCAPED=$(echo "$HASH" | sed -e 's/[\/&]/\\&/g')

# Use sed to replace the integrity attribute in the HTML file
sed -i "s/integrity=\"[^\"]*\"/integrity=\"$HASH_ESCAPED\"/" "$HTML_FILE"

echo "Updated integrity hash in $HTML_FILE to $HASH_ESCAPED"
