const socket = io();
// this is auto-set
const my_id = document.getElementById("sender_id").textContent;
let room_title = document.getElementById("room_title").textContent;
let room_id = document.getElementById("room_id").textContent;

const encryptor = new JSEncrypt();
const myInstance = new JSEncrypt();
let room_key;
let my_private_key;
let connected = 0;

// look at keys or at least maybe idek
if (localStorage.getItem(room_title)) {
  room_key = localStorage.getItem(room_title)
  document.getElementById("room_key").value  = room_key
}
if (localStorage.getItem("private_key")) {
  my_private_key = localStorage.getItem("private_key")
  document.getElementById("private_key").value  = my_private_key
}



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


async function sendMessage() {
  const content = document.getElementById("message").value;
  const encryptedContent = await encrypt(room_key, content);
  console.log(content, room_key);
  console.log(encryptedContent);
  const newParagraph = document.createElement("p");
  newParagraph.textContent = "me: "+ content;
  document.getElementById("messages").appendChild(newParagraph);
  socket.emit("newMessageRoom", {room_title: room_title, room_id: room_id, content: encryptedContent, sender_id: my_id, save: true});
}

function initialize() {
  if (document.getElementById("private_key").value == "") return;
  if (room_key == "") return;
  room_key = document.getElementById("room_key").value
  socket.emit("establishmentRoom", {sender_id: my_id, room_title: room_title, room_id: room_id})
}

function request_key() {
  // Making sure the private key is set before we send the request.
  if (document.getElementById("private_key").value == "") return;
  my_private_key = document.getElementById("private_key").value;
  myInstance.setPrivateKey(my_private_key);
  console.log(myInstance.getPrivateKey());
  socket.emit("requestKey", {sender_id: my_id, room_id: room_id});
}

// Listen for the 'connect' event
socket.on('connect', () => {
    connected=1
    console.log('Connected to Socket.IO server');
});

socket.on('requestKeyForward', (data) => {
  const requester_public_key = data.public_key;
  // Set the one encryptor with the guys public key. This one instance will be re-used
  encryptor.setPublicKey(requester_public_key);
  const encryptedKey = encryptor.encrypt(room_key);
  socket.emit("requestKeyResponse", {encryptedKey, encrypted_username: data.encrypted_username, room_id});
});

socket.on('requestKeyResponseForward', (data) => {
  const { encryptedKey } = data;
  const decryptedKey = myInstance.decrypt(encryptedKey);
  room_key = decryptedKey;
  document.getElementById("room_key").value = room_key;
  if (room_key) connected=2
});



socket.on("establishmentRoom", async (data) => {
    for (let message of data.messages) {
        
        const newParagraph = document.createElement("p");
        let decryptedContent;
        try {
          decryptedContent = await decrypt(room_key, message.content);
        } catch (e) {
          decryptedContent = "ERROR GETTING AND DECRYPTING MESSAGE: e"
          newParagraph.style.color = "red";
        }

        let prefix;
        if (message.sender_id == my_id) {
          prefix = "me: "
        } else {
          prefix = message.sender_username + ": "
        }

        newParagraph.textContent = prefix + decryptedContent;
        document.getElementById("messages").appendChild(newParagraph);
    }
    console.log("established: "+ JSON.stringify(data.messages));
    connected=3
});

socket.on('newMessage', (data) => {
    const { receiver_content, sender_id, signature, save } = data;
    console.log("NEW MESSAGE.")
    console.log(receiver_content, sender_id, signature);
    if (sender_id != my_id) {
        /*
            There is no sender_content - it is unnecessary.
            This part of the code will not be executed for the other guy, who sent the message. 
        */
        let decryptedMessage = decrypt_for_me(receiver_content);
        if (!verify_for_him(decryptedMessage, signature)) {
            newParagraph.style.color = "red";
            decryptedMessage = "MESSAGE COULD NOT BE VERIFIED: " + his_username + ": " + decryptedMessage;
        } else {
            decryptedMessage = his_username + ": " + decryptedMessage;
        }
        const newParagraph = document.createElement("p");
        newParagraph.textContent = decryptedMessage;
        document.getElementById("messages").appendChild(newParagraph)
    }

})

// Listen for incoming messages from the server
socket.on('message', (msg) => {
    const messagesDiv = document.getElementById('messages');
    const messageElement = document.createElement('div');
    messageElement.textContent = msg; // Display the received message
    messagesDiv.appendChild(messageElement); // Append the message to the div
    messagesDiv.scrollTop = messagesDiv.scrollHeight; // Scroll to the bottom
});

document.getElementById("request_key").addEventListener("click", function() {
    request_key();
  });

  document.getElementById("initialize").addEventListener("click", function() {
    initialize();
  });

document.getElementById("sendMessage").addEventListener("click", function() {
    sendMessage();
});

setInterval(() => {
  document.title = room_title + " {" + connected + "}";
}, 100);