async function generateAESKey() {
    const key = await window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256,
        },
        true, // whether the key can be exported
        ["encrypt", "decrypt"]
    );

    // Export the key to raw format
    const exportedKey = await window.crypto.subtle.exportKey("raw", key);
    // Convert ArrayBuffer to Base64 string
    return arrayBufferToBase64(exportedKey);
}

async function importAESKey(base64Key) {
    // Convert Base64 string back to ArrayBuffer
    const rawKey = base64ToArrayBuffer(base64Key);
    // Import the raw key
    return await window.crypto.subtle.importKey(
        "raw",
        rawKey,
        {
            name: "AES-GCM",
        },
        true, // whether the key can be exported
        ["encrypt", "decrypt"]
    );
}

async function encrypt(base64Key, data) {
    const key = await importAESKey(base64Key); // Import the key from its string representation

    const encoder = new TextEncoder();
    const encodedData = encoder.encode(data);

    // Generate a random initialization vector (IV)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // Encrypt the data
    const encryptedData = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        encodedData
    );

    // Combine IV and encrypted data into a single Uint8Array
    const ivAndEncrypted = new Uint8Array(iv.length + encryptedData.byteLength);
    ivAndEncrypted.set(iv); // set IV at the beginning
    ivAndEncrypted.set(new Uint8Array(encryptedData), iv.length); // set encrypted data after IV

    // Convert to base64 string for easy handling
    return btoa(String.fromCharCode(...ivAndEncrypted));
}

async function decrypt(base64Key, combinedData) {
    const key = await importAESKey(base64Key); // Import the key from its string representation

    // Decode the base64 combined data to a Uint8Array
    const ivAndEncrypted = Uint8Array.from(atob(combinedData), c => c.charCodeAt(0));

    // Extract the IV and the encrypted data
    const iv = ivAndEncrypted.slice(0, 12); // first 12 bytes for IV
    const encryptedData = ivAndEncrypted.slice(12); // rest is the encrypted data

    // Decrypt the data
    const decryptedData = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        encryptedData
    );

    // Convert decrypted data back to a string
    const decoder = new TextDecoder();
    return decoder.decode(decryptedData);
}

// Utility functions to convert between ArrayBuffer and Base64
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

async function go() {
    const newKey = await generateAESKey();
    document.getElementById("key").value = newKey;
}

go()

