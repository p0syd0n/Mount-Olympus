// Create a new JSEncrypt object
const encryptor = new JSEncrypt();

// Generate keys
const publicKey = encryptor.getPublicKey();
const privateKey = encryptor.getPrivateKey();

// Log generated keys
console.log("Public Key:", publicKey);
console.log("Private Key:", privateKey);

document.getElementById("public_key").textContent = publicKey;
document.getElementById("private_key").textContent = privateKey;


// Message to encrypt
const message = "Hello, this is a secret message!";

// Set the public key
encryptor.setPublicKey(publicKey);

// Encrypt the message
const encryptedMessage = encryptor.encrypt(message);
console.log("Encrypted Message:", encryptedMessage);

// Set the private key
encryptor.setPrivateKey(privateKey);

// Decrypt the message
const decryptedMessage = encryptor.decrypt(encryptedMessage);
console.log("Decrypted Message:", decryptedMessage);