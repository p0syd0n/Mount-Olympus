const socket = io();
const signage = ""
// these are auto-set
const my_id = document.getElementById("sender_id").textContent;
const his_id = document.getElementById("receiver_id").textContent;
let his_username;
// My instance will encrypt and decrypt things with my public key.
const myInstance = new JSEncrypt();
// His isntance will encrypt things with his public key.
const hisInstance = new JSEncrypt();
let established = false;

// look at keys or at least maybe idek
let hisPublicKey = document.getElementById("his_public_key").value;
let myPrivateKey = localStorage.getItem("private_key");
document.getElementById("my_private_key").value = myPrivateKey;
let myPublicKey = document.getElementById("my_public_key").value;

// Gets called when button is pressed. Will set instances and will call stablishment.
function initialize() {
    // get keys
    myPublicKey = document.getElementById("my_public_key").value;
    hisPublicKey = document.getElementById("his_public_key").value;
    myPrivateKey = document.getElementById("my_private_key").value;

    // Use his public key
    hisInstance.setPublicKey(hisPublicKey);
    console.log("setting my private key");
    myInstance.setPublicKey(myPublicKey);

    let r =  myInstance.setPrivateKey(myPrivateKey);
    console.log("Set: "+r);
    socket.emit("establishment", {sender_id: my_id, receiver_id: his_id});
}


function encrypt_for_me(message) {
    return myInstance.encrypt(message);
}

function sign(message) {
    return myInstance.sign(message, CryptoJS.SHA256, "sha256");
}

function verify_for_him(message, signature) {
    return hisInstance.verify(message, signature, CryptoJS.SHA256);
}

function verify_for_me(message, signature) {
    return myInstance.verify(message, signature, CryptoJS.SHA256);
}

function encrypt_for_him(message) {
    return hisInstance.encrypt(message);
}

function decrypt_for_me(message) {
    return myInstance.decrypt(message);
}

function sendMessage() {
    if (!established) return;
    // const content = data.content;
    // const receiver_id = data.receiver_id;
    // const sender_id = data.sender_id;
    // const save = data.save;
    
    const content = document.getElementById("input").value;

    const newParagraph = document.createElement("p");
    newParagraph.textContent = "me: " + content;
    document.getElementById("messages").appendChild(newParagraph);

    const encryptedContentForMe = encrypt_for_me(content);
    const encryptedContentForHim = encrypt_for_him(content);
    const signature = sign(content);
    socket.emit("sendMessage", {sender_content: encryptedContentForMe, receiver_content: encryptedContentForHim, signature: signature, receiver_id: his_id, sender_id: my_id, save: true});

}

// Listen for the 'connect' event
socket.on('connect', () => {
    console.log('Connected to Socket.IO server');
});

socket.on("establishment", (data) => {
    his_username = data.receiver_username;
    console.log(data.messages)
    for (let message of data.messages) {
        
        const newParagraph = document.createElement("p");
        let decryptedContent;
        try {
            console.log("Message. \n" + message)
            if (message.sender_id == my_id) {
                console.log("this message is from me.")
                /*
                 if i sent the message, decrypt the message version that was encrypted with my public key.
                 This is stored in sender_conteent (content for sender)
                 */
                decryptedContent = decrypt_for_me(message.sender_content);
                if (!verify_for_me(decryptedContent, message.signature)) {
                    decryptedContent = "MESSAGE COULD NOT BE VERIFIED: me: " + decryptedContent;
                    newParagraph.style.color = "red";
                } else {
                    decryptedContent = "me: " + decryptedContent;
                }
                
            } else {
                /* 
                else : i didnt send the message. he did.
                In this case, sender_content has the message encrypted with his public key.
                We need to use receiver_content.
                */
                decryptedContent = decrypt_for_me(message.receiver_content);
                if (!verify_for_him(decryptedContent, message.signature)) {
                    decryptedContent = "MESSAGE COULD NOT BE VERIFIED: " + his_username + ": " + decryptedContent;
                    newParagraph.style.color = "red";
                } else {
                    decryptedContent = his_username + ": " + decryptedContent;
                }
            }
        }
        catch (e) {
            decryptedContent = "ERROR GETTING AND DECRYPTING MESSAGE: e"
            newParagraph.style.color = "red";
        }
        if (decryptedContent == "") return;
        newParagraph.textContent = decryptedContent;
        document.getElementById("messages").appendChild(newParagraph);
    }
    console.log("established: "+ JSON.stringify(data.messages));
    established = true;
})

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

document.getElementById("initialize").addEventListener("click", function() {
    initialize();
  });

document.getElementById("sendMessage").addEventListener("click", function() {
    sendMessage();
});