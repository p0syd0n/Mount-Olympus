const express = require('express');
const path = require('path');
const session = require('express-session');
const dotenv = require('dotenv');
const { fileURLToPath } = require('url');
const { dirname } = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const { prompt, hashPassword, deriveKey } = require('./util.js');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const winston = require('winston');
const cors = require('cors');
const fs = require('fs');
const bodyParser = require('body-parser');
const { Server, Socket } = require('socket.io');
const expressSocketIO = require('express-socket.io-session');
const http = require('http');
const { render } = require('ejs');
const multer = require('multer');
const https = require('https');
const Trie = require('trie-prefix-tree');
const { v4: uuidv4 } = require('uuid');
const { createCanvas } = require('canvas');
const Client = require('bitcoin-core');
const { getTransactions } = require('./blockchain.js');



const db = new Database('database/database.db');

// Load environment variables
dotenv.config();
let encryptionKey;


// const __filename = fileURLToPath(import.meta.url);
// const __dirname = dirname(__filename);
let PORT = 4000;
const topics = {0: "general"}


const app = express();
let server;
// Check global variable if deploy is 1. If it is, get ssl certs and start https server
if (process.env.DEPLOY == "1") {
    const sslOptions = {
        key: fs.readFileSync('/etc/letsencrypt/live/23-92-19-124.ip.linodeusercontent.com/privkey.pem'),
        cert: fs.readFileSync('/etc/letsencrypt/live/23-92-19-124.ip.linodeusercontent.com/fullchain.pem'),
    };
    server = https.createServer(sslOptions, app);
    PORT = 442;
}
else {
    // Otherwise, start http server.
    server = http.createServer(app);
}
// Socket server
const io = new Server(server);
// Listing valid auth tokens and request tokens
let validAuthTokens = [];
let requestTokens = {};
let ordersPending = {};

const captchaMap = new Map();
// Log path
const logPath = "app.log";
// Dictionaries for later O(1) access
let usernameToId = {}
let roomNameToId = {}

const storage = multer.memoryStorage(); // Store files in memory as Buffer
const upload = multer({ storage: storage });


const client = new Client({
    network: 'testnet', // or 'testnet', 'regtest'
    username: process.env.USERNAME_BTC,
    password: process.env.PASSWORD_BTC,
    host: process.env.HOST_BTC,
    port: process.env.PORT_BTC
});

setInterval(() => {
    const now = Date.now();
    const expiryTime = 3 * 60 * 1000; // 3 minutes
    captchaMap.forEach((id, entry) => {
        if (now - entry.timestamp > expiryTime) {
            captchaList.delete(id);
        }
    });
}, 2 * 60 * 1000); // 2 minutes


/*
Request flow:
HTTP GET /createOrder
it hits /createOrder, and goes thru default stuff
After that, middleware picks it up and adds captcha data to res.locals
Middleware also adds captcha data to captchaMap
HTTP POST /executeCreateOrder
captchaId is in a hidden field, captchaCode is input by the user
They are checked against captchaMap to verify
*/

function captchaMiddleware(req, res, next) {
    const canvas = createCanvas(100, 40);
    const ctx = canvas.getContext('2d');

    // Generate random CAPTCHA code
    const captchaCode = Math.random().toString(36).substring(2, 6).toUpperCase();
    const captchaId = uuidv4(); // Unique ID for this CAPTCHA

    // Draw CAPTCHA
    ctx.fillStyle = '#f0f0f0';
    ctx.fillRect(0, 0, 100, 40);
    ctx.font = '28px Arial';
    ctx.fillStyle = '#000';
    ctx.fillText(captchaCode, 10, 30);

    captchaMap.set(captchaId, { code: captchaCode, timestamp: Date.now() });
    const base64 = canvas.toDataURL();
    res.locals.captchaId = captchaId
    res.locals.captchaImage = base64;

    next();
}
// Set strong CSP policies
const cspPolicy = {
    directives: {
        defaultSrc: ["'self'"], // Only allow resources from the same origin
        scriptSrc: [
            "'self'",
            "'unsafe-eval'", // Allow eval for WebAssembly, ig
            "https://cdnjs.cloudflare.com", // Allow scripts from the domain
            // + Specific hashes for inline scripts if necessary
        ],
        objectSrc: ["'none'"], // Disallow all plugins like Flash
        baseUri: ["'self'"], // Only allow base tag to point to the domain
        formAction: ["'self'"], // Forms can only submit to the domain
        frameAncestors: ["'none'"], // Prevent the page from being framed
        upgradeInsecureRequests: [], // Automatically upgrade HTTP requests to HTTPS
        blockAllMixedContent: [], // Block mixed content (HTTP on HTTPS pages)
        reportUri: "/csp-violation-report", // this line for reporting
    },
};

// Define custom logging levels
const customLevels = {
    levels: {
        csp_violation: 0,
        fatal: 0,  // Critical system errors
        error: 1,  // Regular errors
        warn: 2,   // Warnings
        info: 3,   // General info messages
        verbose: 4, // More detailed messages
        debug: 5,  // Debugging information
        trace: 6   // Very detailed tracing information
    },
    colors: {
        csp_violation: 'red',
        fatal: 'red',
        error: 'red',
        warn: 'yellow',
        info: 'green',
        verbose: 'cyan',
        debug: 'blue',
        trace: 'magenta'
    }
};

// Create the logger with custom levels
const logger = winston.createLogger({
    levels: customLevels.levels,
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            const encrypted = encrypt(message); // Encrypt the message
            return `${timestamp} [${level}]: ${JSON.stringify(encrypted)}`; // Log the encrypted message
        })
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(), // Colorize console output
                winston.format.timestamp(), // Include timestamp
                winston.format.printf(({ timestamp, level, message }) => {
                    //const encrypted = encrypt(message);
                    return `${timestamp} [${level}]: ${message}`;
                })
            )
        }),
        new winston.transports.File({ filename: 'app.log' }) // Log to a file
    ],
});

// Add custom colors to the console
winston.addColors(customLevels.colors);

// For searching products by name
let product_names_tree = Trie([]);
let tag_names_dict = {};
let name_product_dict = {};

/**
 * Generate a new address
 * @returns {string} the address
 */
async function generateNewAddress() {
    try {
        const address = await client.getNewAddress(); // Optionally pass a label and address type
        return address;
    } catch (error) {
        return false;
    }
}

/**
 * Repopulated the product names trie and dict
 */
function rePopulateTrieAndDict() {
    // Reset the Trie and Tag Dictionary once at the beginning
    product_names_tree = Trie([]);
    tag_names_dict = {};
    name_product_dict = {};

    // Fetch all products
    const products = db.prepare("SELECT * FROM catalogue").all(); // Assuming `.all()` fetches all records as an array

    for (let product of products) {
        // const data = {
        //     id: product.id,
        //     name: decrypt(product.name),
        //     tags: decrypt(product.tags),
        //     name_hash: product.name_hash,
        //     notes: decrypt(product.notes),
        //     vendor_id: product.vendor_id,
        //     description: decrypt(product.description),
        //     price: decrypt(product.price),
        //     image: isItReal(product.image) ? decrypt(product.image) : "",
        //     system_price: product.system_price,
        //     verified_buyers: isItReal(product.verified_buyers) ? product.verified_buyers : "",
        //     address: product.address ? decrypt(product.address) : null,
        //     system_payments: product.system_payments,
        //     reviews: isItReal(product.reviews) ? decrypt(product.reviews) : "",
        //     buys: product.buys,
        //     created_time: product.created_time
        // };
        const data = {
            id: product.id,
            name: product.name,
            tags: product.tags,
            name_hash: product.name_hash,
            notes: product.notes,
            vendor_id: product.vendor_id,
            description: product.description,
            price: product.price,
            image: product.image,
            system_price: product.system_price,
            verified_buyers: product.verified_buyers,
            address: product.address,
            system_payments: product.system_payments,
            reviews: product.reviews,
            buys: product.buys,
            created_time: product.created_time
        };
        name_product_dict[decrypt(product.name)] = product;

        // Add product name to Trie with associated data
        product_names_tree.addWord(decrypt(data.name));

        // Process tags
        const tags = decrypt(data.tags).split(',').map(tag => tag.trim()); // Ensure tags are trimmed
        // The tag_names_dict is structured as so:
        /*
        {
            "tag1": [ Array of posts with tag tag1 ]
            "tag2": [ Array of posts with tag tag2 ]
        }
        */
        for (let tag of tags) {
            if (tag_names_dict[tag]) {
                tag_names_dict[tag].push(data);
            } else {
                tag_names_dict[tag] = [data];
            }
        }
    }
    //console.log(tag_names_dict)
}




/**
 * Search  for all posts with any of the specified tags
 * @param {string} tags comma-seperated list of tags
 */
function searchTagsOR(tags) {
    // Split the input into individual tags and trim whitespace
    const tagsArray = tags.split(',').map(tag => tag.trim());

    // A Set to store unique products
    let resultSet = new Set();

    // Loop over each tag, find matching products, and add them to the result set
    tagsArray.forEach(tag => {
        const products = tag_names_dict[tag];
        if (products) {
            products.forEach(product => {
                resultSet.add(product); // Add product to the result set
            });
        }
    });

    // Return the products as an array
    return Array.from(resultSet);
}

/**
 * Search for all posts with all of the specified tags.
 * @param {string} tags comma-seperated list of tags
 */
function searchTagsAND(tags) {
    // Split the input into individual tags and trim whitespace
    const tagsArray = tags.split(',').map(tag => tag.trim());

    // Initialize an array for products that match all tags
    let result = [];

    // Find products for the first tag
    const firstTagProducts = tag_names_dict[tagsArray[0]];
    if (!firstTagProducts) return []; // No products for the first tag

    // Filter products that match all the tags
    result = firstTagProducts.filter(product => {
        // Check if the product has all tags
        return tagsArray.every(tag => product.tags.split(',').map(t => t.trim()).includes(tag));
    });

    return result;
}


/**
 * Update the username : id dictionary
 */
function updateUsernameToId() {
    const stmt = db.prepare("SELECT * FROM users;");
    const result = stmt.all();
    for (let user of result) {
        usernameToId[decrypt(user.username)] = user.id;
    }
}

/**
 * Update the room : id dictionary
 */
function updateRoomToId() {
    const stmt = db.prepare("SELECT * FROM rooms;");
    const result = stmt.all();
    for (let room of result) {
        roomNameToId[decrypt(room.title)] = room.id;
    }
}





/**
 * Encrypt data using AES-256-CBC with a random IV.
 * @param {string} data - The plaintext data to encrypt.
 * @returns {string} - The IV + encrypted ciphertext in hex format.
 */
function encrypt(data) {
    // Generate a random IV for each encryption
    const IV = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, IV);

    let encrypted = cipher.update(data, 'utf-8', 'hex');
    encrypted += cipher.final('hex');

    // Prepend IV to the encrypted result
    const ivHex = IV.toString('hex');
    return ivHex + encrypted;
}

/**
 * Decrypt data using AES-256-CBC with the IV stored in the ciphertext.
 * @param {string} encryptedData - The IV + encrypted data in hex format.
 * @returns {string} - The decrypted plaintext.
 */
function decrypt(encryptedData) {
    // Extract IV from the beginning of the encrypted data
    const ivHex = encryptedData.slice(0, 32); // First 32 hex characters (16 bytes)
    const IV = Buffer.from(ivHex, 'hex');
    
    // Extract the actual ciphertext
    const ciphertext = encryptedData.slice(32);
    const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, IV);

    let decrypted = decipher.update(ciphertext, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');

    return decrypted;
}

/**
 * Get the public key from a user_id
 * @param {int} user_id the user id of who you want to get the public key
 * @returns public key, string. Except if the user doesnt exist: -1
 */
function getPublicKey(user_id) {
    const stmt = db.prepare(`SELECT public_key FROM users WHERE id = ?`);
    const result = stmt.get(user_id);
    return result ? result.public_key : -1
}

/**
 * is a string real or is it the square root of -1 ? That is the question
 * @param {string} value just checks if a variable is a string and not empty.
 * @returns boolean
 */
function isItReal(value) {
    return typeof value === 'string' && value.trim().length > 0;
}

/**
 * Get vendor data from his id
 * @param {int} vendor_id the id of the vendor
 * @returns object with data
 */
function getVendorData(vendor_id) {
    const stmt = db.prepare(`SELECT * FROM vendors WHERE id = ?`);
    return stmt.get(vendor_id);
}
/**
 * Get user data by his id
 * @param {int} user_id the user_id of the user
 * @returns object with data
 */
function getUser(user_id) {
    const stmt = db.prepare(`SELECT * FROM users WHERE id = ?`);
    return stmt.get(user_id);
}

function setPfp(user_id, pfp_base64) {
    const stmt = db.prepare(`UPDATE users SET pfp = ? WHERE id = ?`); // Removed "TABLE"
    return stmt.run(pfp_base64, user_id);
}


/**
 * Get all logs.
 * @returns logs [DECRYPTED]
 */
function getAllDecryptedLogs() {
    try {
        // Read the log file
        const logData = fs.readFileSync(logPath, 'utf8');

        // Split log entries (assuming each entry is on a new line)
        const logEntries = logData.split('\n').filter(Boolean); // Filter out any empty lines
        let log = []
        for (let entry of logEntries) {
            const split_ = entry.split(" ");
            const time = split_[0];
            const type = split_[1];
            const data_encrypted = split_[2].replace("\"", "").replace("\"", "");
            const data_decrypted = decrypt(data_encrypted);
            log.push(`${time} ${type} ${data_decrypted}`);
        }

        // Filter out any null values from decryption failures
        return log; 
    } catch (error) {
        console.error('Error reading log file:', error);
        return []; // Return an empty array if there's an error
    }
}

function getProductData(vendor_id, product_name) {
    try {
        const hashedName = hashPassword(product_name);
        // Prepare and execute the SQL query to get the product details
        const query = db.prepare(`
            SELECT * FROM catalogue 
            WHERE vendor_id = ? AND name_hash = ?;
        `);
        const result = query.get(vendor_id, hashedName);
        
        // If result is found, return it; otherwise, return null
        return result || null;
    } catch (error) {
        console.error("Error fetching product:", error);
        return null;
    }
}

function getProductDataById(product_id) {
    try {
        // Prepare and execute the SQL query to get the product details
        const query = db.prepare(`
            SELECT * FROM catalogue 
            WHERE id = ?;
        `);
        const result = query.get(product_id);
        
        // If result is found, return it; otherwise, return null
        return result || null;
    } catch (error) {
        console.error("Error fetching product:", error);
        return null;
    }
}

/**
 * Delete a room by its id
 * @param {int} roomId the id of the room to delete
 * @returns {int} 1 in case of success
 */
function deleteRoom(roomId) {
    const stmt = db.prepare(`DELETE FROM rooms WHERE id = ?`);
    stmt.run(roomId);
    const stmt2 = db.prepare(`DELETE FROM messages WHERE room_id = ?`);
    stmt2.run(roomId);
    return 1;
}

/**
 * Add a message to the database. Message content should be encrypted with the server symmetrical key prior to being added.
 * @param {int} user_id_from the id of the user who is sending the message
 * @param {int} user_id_to the id of the user who is receiving the message
 * @param {string} sender_content the sender content (the content of the message, encrypted with the public key of the sender). This function expects it to already be encrypted with the server symmetrical key.
 * @param {string} receiver_content the receiver content (the content of the message, encrypted with the public key of the receiver). This function expects it to already be encrypted with the server symmetrical key.
 * @param {string} signature the signature of the message. (The signed sha256 hash of the message, signed by sender.) This function expects it to already be encrypted with the server symmetrical key.
 * @returns result of SQL query
 */
function createMessage(user_id_from, user_id_to, sender_content, receiver_content, signature) {
    const username_from = getUsernameById(user_id_from);
    const username_to = getUsernameById(user_id_to);
    
    const encrypted_username_from = encrypt(username_from);
    const encrypted_username_to = encrypt(username_to);
    // Its encrypted in the socket code
    const encrypted_sender_content = sender_content;
    const encrypted_receiver_content = receiver_content;
    const encrypted_signature = signature;

    let users;
    if (user_id_to > user_id_from) {
        users = `${user_id_to},${user_id_from}`;
    } else {
        users = `${user_id_from},${user_id_to}`;
    }
    const stmt = db.prepare(`INSERT INTO direct_messages (user_id_from, username_from, user_id_to, username_to, sender_content, receiver_content, users, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
    return stmt.run(user_id_from, encrypted_username_from, user_id_to, encrypted_username_to, encrypted_sender_content, encrypted_receiver_content, users, encrypted_signature);

}

/**
 * Get messages between two users. Encrypted
 * @param {string} users comma seperated list of user ids - bigger one first. Used to identify direct messages.
 * @returns list of messages which have the `users` attribute of your argument
 */
function getMessages(users) {
    const stmt = db.prepare(`SELECT * FROM direct_messages WHERE users = ?`);
    return stmt.all(users);
}
/**
 * Convert USD to BTC
 * @param {int} usdAmount USD amount
 * @returns {double} Probably a double containing the BTC amount
 */
async function convertUsdToBtc(usdAmount) {
    try {
      // Fetch the current BTC price in USD from CoinGecko
      const response = await axios.get('https://api.coingecko.com/api/v3/simple/price', {
        params: {
          ids: 'bitcoin',
          vs_currencies: 'usd',
        },
      });
  
      const btcPriceInUsd = response.data.bitcoin.usd;
  
      if (!btcPriceInUsd) {
        throw new Error('Failed to retrieve BTC price');
      }
  
      // Calculate the BTC amount
      const btcAmount = usdAmount / btcPriceInUsd;
  
      return btcAmount;
    } catch (error) {
      console.error('Error converting USD to BTC:', error.message);
      throw error;
    }
  }

/**
 * 
 * @param {string} address The address which you are checking
 * @returns {int} The amount that has been recieved by said address
 */
  async function getTotalReceivedByAddress(address) {
    try {
      // Get the total amount received by the address
      const totalReceived = await client.getReceivedByAddress(address);
      logger.info(`Address ${address} has received a total of ${totalReceived} BTC`);
      return totalReceived;
    } catch (error) {
      logger.error(`Error fetching received amount for address ${address}:`, error.message);
      throw error;
    }
  }
/**
 * Update the account for a vendor.
 * @param {int} vendor_id The id of the vendor to update
 * @param {string} vendor_name The vendor name to be set
 * @param {string} email The email of the vendor to be set
 * @param {string} about The "about" of the vendor to be set
 * @param {string} tags The tags of the vendor to be set
 * @returns Result of SQL query
 */
function updateVendorSettings(vendor_id, vendor_name, email="", about="", tags="") {
    const encryptedName = encrypt(vendor_name);
    const encryptedEmail = encrypt(email);
    const encryptedAbout = encrypt(about);
    const encryptedTags = encrypt(tags);
    const stmt = db.prepare(`UPDATE vendors SET vendor_name = ?, email = ?, tags = ?, about = ? WHERE id = ?`);
    return stmt.run(encryptedName, encryptedEmail, encryptedTags, encryptedAbout, vendor_id);
}

/**
 * Get posts from a specified topic_id and with an order
 * @param {int} topic_id int indicating topic_id in database. Defaults to 0 (general)
 * @param {order} order sorting order. Defaults to "ORDER BY aura DESC" (top aura at top)
 * @returns Result of SQL query
 */
async function getPosts(topic_id, order="desc_aura") {
    let order_suffix;
    // Times ascending = oldest to newest
    switch (order) {
        case "desc_aura":
            order_suffix = "ORDER BY aura DESC";
            break;
        case "asc_aura":
            order_suffix = "ORDER BY aura ASC";
            break;
        case "latest":
            order_suffix = "ORDER BY time_created DESC";
            break;
        case "oldest":
            order_suffix = "ORDER BY time_created ASC";
            break;
        default:
            order_suffix = "ORDER BY aura DESC";
            break;
    }
    const query = `SELECT * FROM posts WHERE topic_id = ? ${order_suffix}`;
    const stmt = db.prepare(query);
    return stmt.all(topic_id);
    
}

/**
 * Delete the conversation between two users (delete all messages between them)
 * @param {string} users The users parameter of the conversation
 * @returns The result of the SQL query
 */
async function deleteConversation(users) {
    const stmt = db.prepare("DELETE FROM direct_messages WHERE users=?");
    return stmt.run(users);
}

/**
 * Get users from the database. Returns encrypted data.
 * @returns {Array}  List of users. [ENCRYPTED]
 */
async function getUsers() {
    const stmt = db.prepare("SELECT * FROM users;");
    const result = await stmt.all();
    return result;
}

async function checkCaptcha(req) {
    try {
        if (captchaMap.has(req.body.captchaId) && captchaMap.get(req.body.captchaId).code === req.body.captchaCode) {
            logger.debug("Valid CAPTCHA");
            try {
                captchaMap.delete(req.body.captchaId); // Remove after use
            } catch (e) {
                logger.error("Failed to delete captcha from the map");
            }
            return true;
        } else {
            logger.debug("Invalid CAPTCHA");
            return false;
        }
    } catch (e) {
        return false;
    }

}

/**
 * Create user. Will automatically encrypt data..
 * @param {string} username - Username for new user.
 * @param {string} password - Plaintext password for new user. Will be hashed automatically.
 * @param {boolean} admin - Boolean indicating whether the user is an admin
 * @returns {string} The result of the SQL query.
 */
async function createUser(username, password, admin, about="", public_key="", global_bool=1, pfp="", tags="", email="", vendor_id=null) {
    let newpfp
    if (pfp == "") {
        fs.readFile("public/images/image.png", (err, data) => {
            if (err) {
                console.error('Error reading the file:', err);
                return;
            }

            // Convert to Base64
            const base64String = data.toString('base64');
            newpfp = base64String
        });
    } else {
        newpfp = pfp;
    }
    const hashedPassword = await bcrypt.hash(password, 10);  // Hash the password
    const encryptedUsername = encrypt(username);
    const encryptedPassword = encrypt(hashedPassword);
    const encryptedAbout = isItReal(about) != "" ? encrypt(about) : "";
    const encryptedPublicKey = isItReal(public_key) != "" ? encrypt(public_key) : "";
    const encryptedTags = isItReal(tags) != "" ? encrypt(tags) : "";
    const encryptedEmail = isItReal(email) != "" ? encrypt(email) : "";
    


    //console.log(encryptedUsername, encryptedPassword);
    const stmt = db.prepare('INSERT INTO users (username, password, admin, aura, about, public_key, global, pfp, tags, email, vendor_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
    return stmt.run(encryptedUsername, encryptedPassword, admin, 0, encryptedAbout, encryptedPublicKey, global_bool, newpfp, encryptedTags, encryptedEmail, vendor_id).lastInsertRowid;
}
/**
 * 
 * @param {int} roomId the id of the room who's messages you want
 * @returns 
 */
function getMessagesRoom(roomId) {
    const stmt = db.prepare(`SELECT * FROM messages WHERE room_id = ?`);
    return stmt.all(roomId);
}

/**
 * Create an order
 * @param {int} buyer_id The id of the buyer
 * @param {int} product_id The id of the product
 * @param {int} amount The amount of products bought
 * @returns Result of the SQL query
 */
function createOrder(product_id, user_id, amount, vendor_id, estimated_arrival) {
    if (amount <= 0 || user_id <= 0 || amount <= 0 || vendor_id <= 0) return -1;
    const stmt = db.prepare(`INSERT INTO orders (product_id, user_id, amount, vendor_id, estimated_arrival, shipment_proof, recieved) VALUES (?, ?, ?, ?, ?, ?, ?)`);
    const encrypted_product_id = encrypt(product_id.toString());
    const encrypted_user_id = encrypt(user_id.toString());
    const encrypted_amount = encrypt(amount.toString());
    const encrypted_vendor_id = encrypt(vendor_id.toString());
    const encrypted_estimated_arrival = encrypt(estimated_arrival);
    const result = stmt.run(encrypted_user_id, encrypted_user_id, encrypted_amount, encrypted_vendor_id, encrypted_estimated_arrival, "", false);
    return result;
}

/**
 * 
 * @param {int} user_id The user id 
 * @returns {array} [{ user_id: id, username: username }]
 */
async function getUsersForDMs(user_id) {
    const stmt = db.prepare("SELECT users FROM direct_messages;");
    const result = await stmt.all();
    let refined = [];
    for (let entry of result) {
        refined.push(entry.users);
    }

    const users = refined.filter((value, index, self) => self.indexOf(value) === index);
    const final_array  = []
    for (let user_pair of users) {
        let user1 = user_pair.split(",")[0];
        let user2 = user_pair.split(",")[1];
        let other_user = (user1 == user_id) ? user2 : user1;
        const other_user_username = decrypt(getUsernameById(other_user));
        final_array.push({user_id: other_user, username: other_user_username});
    }
    return final_array;
}


/**
 * 
 * @param {int} roomId The id of the room
 * @param {string} content the content of the message (THE FUNCTION EXPECTS IT TO BE PRE-ENCRYPTED)
 * @param {int} user_id The id of the user who created the message
 * @returns 
 */
function createMessageRoom(roomId, content, user_id) {
    const stmt = db.prepare(`INSERT INTO messages (content, user_id, room_id) VALUES (?, ?, ?)`);
    return stmt.run(content, user_id, roomId)
}

/**
 * Add a public key to an account
 * @param {int} user_id user id of the account to which you are adding a public key
 * @param {int} public_key the public key. Copy and pasted from /generateKeypair
 * @returns result of sql query, and -1 if it fails
 */
async function addPublicKey(user_id, public_key) {
    const encryptedPublicKey = isItReal(public_key) ? encrypt(public_key) : "";
    if (encryptedPublicKey === "") {
        return -1; // Exit the function if encryptedPublicKey is an empty string
    }
    const stmt = db.prepare(`UPDATE users SET public_key=? WHERE id = ?`);
    return stmt.run(encryptedPublicKey, user_id);
}

/**
 * Get chat rooms
 * @returns result of SQL query [ENCRYPTED]
 */
async function getRooms() {
    const stmt = db.prepare("SELECT * FROM rooms");
    return stmt.all();
}

/**
 * Get products by a vendor's id
 * @param {int} vendor_id The vendor id of who's products you want to get
 * @returns List of products
 */
function getProducts(vendor_id) {
    const stmt = db.prepare(`SELECT * FROM catalogue WHERE vendor_id = ?`)
    return stmt.all(vendor_id);
}

/**
 * Create a chatroom
 * @param {string} title title of chatroom
 * @param {string} password plaintext password for the room
 * @returns 
 */
async function createRoom(title, password="", locked=0) {
    const encryptedTitle = encrypt(title);
    // SHA-512
    const hashedPassword = password == "" ? "" : await hashPassword(password);
    const encryptedHashedPassword = hashedPassword == "" ? "" : await encrypt(hashedPassword);
    const stmt = db.prepare(`INSERT INTO rooms (title, password, locked) VALUES (?, ?, ?)`);
    stmt.run(encryptedTitle, encryptedHashedPassword, locked).lastInsertRowid;

    const stmt1 = db.prepare(`SELECT id from rooms WHERE title = ?`)
    const room = stmt1.get(encryptedTitle);
    return room ? room.id : -1;
}

/**
 * Create a topic
 * @param {string} title Title of the topic to be created
 * @returns result of SQL query
 */
async function createTopic(title) {
    const encryptedTitle = encrypt(title);
    const stmt = db.prepare("INSERT INTO topics (title, amount) VALUES (?, ?)");
    return stmt.run(encryptedTitle, 0);
}

/**
 * Get post data by id.
 * @param {string} postId - The id of the post which you are looking for.
 * @returns {string} The post data (if the SQL doesn't fail).[ENCRYPTED]
 */
function getPostById(postId) {
    logger.debug("getting post "+postId)
    const stmt = db.prepare('SELECT * FROM posts WHERE id = ?');
    return stmt.get(postId); // Returns a single post as an object
}

/**
 * Get comment data by id.
 * @param {string} commentId - The id of the comment which you are looking for.
 * @returns {string} The comment data (if the SQL doesn't fail).[ENCRYPTED]
 */
function getCommentById(commentId) {
    const stmt = db.prepare('SELECT * FROM comments WHERE id = ?');
    const result = stmt.get(commentId); // Returns a single post as an object
    return result;
}

/**
 * Get room title from its id
 * @param {int} roomId The id of the room
 * @returns title of room or -1
 */
function getRoomTitleById(roomId) {
    const stmt = db.prepare('SELECT title FROM rooms WHERE id = ?');
    const room = stmt.get(roomId);
    return room ? room.title : -1;    
}

/**
 * Get room data from its id
 * @param {int} roomId The id of the room
 * @returns data of room or -1
 */
function getRoomData(roomId) {
    const stmt = db.prepare('SELECT * FROM rooms WHERE id = ?');
    const room = stmt.get(roomId);
    return room ? room : -1;    
}

/**
 * Get a users username from his id.
 * @param {string} userId - The id of the desired user.
 * @returns {string} The username. [ENCRYPTED]
 */
function getUsernameById(userId) {
    const stmt = db.prepare('SELECT username FROM users WHERE id = ?');
    const user = stmt.get(userId);
    return user ? user.username : null;
}

/**
 * Get an id from a username
 * @param {string} username username of the person who's id you want
 * @returns the id (int) or null if the user doesnt exist
 */
function getIdByUsername(username) {
    const encryptedUsername = encrypt(username);
    const stmt = db.prepare('SELECT id FROM users WHERE username = ?');
    const user = stmt.get(encryptedUsername);
    return user ? user.id : null;
}

/**
 * Create a new product
 * @param {int} vendor_id The vendor id of who is creating the product
 * @param {string} name The name of the product
 * @param {string} description The description of the product
 * @param {string} price The shown price
 * @param {string} tags The products tags
 * @param {string} notes Notes about the product
 * @param {string} image Image for product (base64)
 * @param {int} system_price System price per unit. Eg, selling 20 USD / 5 spoons = 20
 * @param {string} address BTC address for this product
 * @param {boolean} system_payments Whether the product is to use system payments
 * @returns Result of the SQL query
 */
async function createProduct(vendor_id, name, description, price, tags, notes, image, system_price=null, address=null, system_payments=true) {
    try {

        // Encrypt all values, ensure encrypt is async if it involves promises
        const encryptedName = await encrypt(name);
        const hashedName = await hashPassword(name);
        const encryptedDescription = await encrypt(description);
        const encryptedPrice = await encrypt(price);
        const encryptedNotes = await encrypt(notes);
        const encryptedImage = await encrypt(image);
        const encryptedTags = await encrypt(tags);
        
        // Handle system_price encryption
        const encryptedSystemPrice = system_payments ? await encrypt(system_price) : null; // null instead of -1 if no system_price is provided
        const encryptedAddress = system_payments ? await encrypt(address) : null;

        // Prepare the statement for insertion
        const stmt = db.prepare(`
            INSERT INTO catalogue (vendor_id, description, price, notes, name, name_hash, image, system_price, verified_buyers, address, system_payments, reviews, buys, tags) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        // Run the query
        const result = stmt.run(vendor_id, encryptedDescription, encryptedPrice, encryptedNotes, encryptedName, hashedName, encryptedImage, encryptedSystemPrice, "", encryptedAddress, system_payments, "", 0, encryptedTags);
        rePopulateTrieAndDict()
        return result;
    } catch (error) {
        console.error("Error creating product:", error);
        throw error; // Rethrow or handle the error as needed
    }
}


/**
 * Create a vendorship (associated with a user account)
 * @param {int} user_id The user id of who is creating a vendorship
 * @param {string} about "about" the vendor
 * @param {string} email The email of the vendor
 * @param {string} tags Comma-seperated list of tags for the vendor
 * @param {string} vendor_name The name of the vendor
 * @returns Result of SQL query
 */
function createVendorship(user_id, about, email, tags, vendor_name) {
    const encryptedAbout = encrypt(about);
    const encryptedEmail = encrypt(email);
    const encryptedTags = encrypt(tags);
    const encryptedVendorName = encrypt(vendor_name);
    const stmt = db.prepare(`INSERT INTO vendors (user_id, about, email, tags, vendor_name) VALUES (?, ?, ?, ?, ?)`);
    stmt.run(user_id, encryptedAbout, encryptedEmail, encryptedTags, encryptedVendorName);

    const stmt2 = db.prepare(`SELECT id FROM vendors WHERE user_id = ?`);
    const user = stmt2.get(user_id);
    
    if (user) {
        const stmt0 = db.prepare(`UPDATE users SET vendor_id = ?`);
        return stmt0.run(user.id);
    } else {
        logger.error("Failed to create vendorship for vendor name " + vendor_name);
        return -1;
    }
}

/**
 * Get products by the amount of buys they have
 * @returns List of products by the amount of buys they have (descending)
 */
function getProductsByBuys() {
    const stmt = db.prepare("SELECT * FROM catalogue ORDER BY buys DESC");
    return stmt.all();
}

/**
 * Gets a users aura from his id.
 * @param {string} userId - The id of the desired user.
 * @returns {string} The aura. [ENCRYPTED]
 */
function getAuraById(userId) {
    const stmt = db.prepare('SELECT aura FROM users WHERE id = ?');
    const user = stmt.get(userId);
    return user ? user.aura : null;
}

/**
 * Gets comments with specified post_id and order
 * @param {int} post_id id of the post for which you are getting comments to
 * @param {string} order how the comments should be sorted
 * @returns result of SQL query
 */
function getComments(post_id, order="aura_desc") {
    let order_suffix;
    // Times ascending = oldest to newest
    switch (order) {
        case "aura_desc":
            order_suffix = "ORDER BY aura DESC";
        case "aura_asc":
            order_suffix = "ORDER BY aura ASC";
        case "latest":
            order_suffix = "ORDER BY time_created DESC";
        case "oldest":
            order_suffix = "ORDER BY time_created ASC";
        default:
            order_suffix = "ORDER BY aura DESC";
    }
    const query = `SELECT * FROM comments WHERE post_id = ? ${order_suffix}`;
    const stmt = db.prepare(query);
    return stmt.all(post_id);
}

/**
 * Add or subtract aura from a user.
 * @param {string} userId - The id of the target user.
 * @param {int} amout - The amount of aura
 * @returns {boolean} true/false depending on success.
 */
function plusMinusAura(userId, amount) {
    const currentAura = getAuraById(userId);
    if (currentAura === null) return false;

    const newAura = currentAura + amount;
    const updateStmt = db.prepare('UPDATE users SET aura = ? WHERE id = ?');
    return updateStmt.run(newAura, userId).changes > 0; // Returns true if the update succeeded
}

/**
 * Vote on a piece of content.
 * @param {int} id - The id of the target piece of content.
 * @param {string} userId - The id of the author (user).
 * @param {string} action - "up"/"down" depending on upvote/downvote
 * @param {string} type - "post"/"comment" 
 * @returns {string} The result of the SQL query.
 */
async function voteContent(id, userId, action, type) {
    let content;
    if (type == 'post') {
        content = await getPostById(id);
    } else if (type == 'comment') {
        content = await getCommentById(id); // Assuming getCommentById is implemented
    } else {
    }

    if (!content) return false;

    const votedUsers = content.voted_user_ids ? content.voted_user_ids.split(',') : [];
    if (votedUsers.includes(String(userId))) return false; // Already voted

    // Calculate new content aura
    const newAura = action === 'up' ? content.aura + 1 : content.aura - 1;

    plusMinusAura(content.user_id, action === 'up' ? 1 : -1); // Adjust user aura (giving the poster aura)

    votedUsers.push(String(userId));
    const updatedVotedUsers = votedUsers.join(',');

    const table = type === 'post' ? 'posts' : 'comments';
    const stmt = db.prepare(`UPDATE ${table} SET aura = ?, voted_user_ids = ? WHERE id = ?`);
    const result = stmt.run(newAura, updatedVotedUsers, id).changes > 0;
}

/**
 * Create a post.
 * @param {string} title The title of the post.
 * @param {int} topicId The (numerical) id of the topic.
 * @param {int} userId The (numerical) id of the author (user).
 * @param {string} content The content of the post.
 * @param {string} tags The tags attached to the post (comma seperated list).
 * @returns {string} The result of the SQL query.
 */
function createPost(title, topicId, userId, content, tags) {
    const encryptedTitle = encrypt(title);
    const encryptedContent = encrypt(content);
    const encryptedTags = encrypt(tags);

    const stmt = db.prepare(`
        INSERT INTO posts (title, topic_id, user_id, content, tags, aura, voted_user_ids)
        VALUES (?, ?, ?, ?, ?, 0, '')
    `);
    return stmt.run(encryptedTitle, topicId, userId, encryptedContent, encryptedTags).lastInsertRowid;
}

/**
 * 
 * @param {int} postId The (numerical) id of the parent post.
 * @param {int} userId The (numerical) id of the author (user).
 * @param {string} content The content of the comment.
 * @returns {string} The result of the SQL query.
 */
function createComment(postId, userId, content) {
    const encryptedContent = encrypt(content)
    const stmt = db.prepare(`
        INSERT INTO comments (post_id, user_id, content, aura, voted_user_ids)
        VALUES (?, ?, ?, 0, '')
    `);
    return stmt.run(postId, userId, encryptedContent).lastInsertRowid;
}

/**
 * 
 * @param {int} severity Level of severity.
 * 0: debug
 * 1: info_unimportant
 * 2: info_important
 * 3: issue 
 * 4: critical_issue 
 * 5: CSP violation
 * @param {string} title Title of message
 * @param {string} content Content of message
 */














// Setting up server
app.set('view engine', 'ejs');
app.use(express.static(__dirname + '/public'));
app.set('views', path.join(__dirname, '/public/views'));
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.json()); // Make sure this is before your routes
app.use(['/createAccount', '/roomLogin', '/createOrder', '/createPost', '/createProduct', '/createRoom', '/vendorshipRegister', '/login'], captchaMiddleware);
app.use(helmet.contentSecurityPolicy(cspPolicy));
const sessionMiddleware = session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
})
app.use(sessionMiddleware);

io.use(expressSocketIO(sessionMiddleware, {
    autoSave: true // Save session changes automatically
}));


















// Routes

app.post("/test", (req, res) => {
    logger.info(req.body);
});

// Reporting endpoint for CSP violations
app.post('/csp-violation-report', (req, res) => {
    const cspReport = req.body['csp-report'] || req.body; // Ensure we access the right structure
    logger.csp_violation('CSP Violation Report:', {
        documentUri: cspReport['document-uri'],
        referrer: cspReport.referrer,
        blockedUri: cspReport['blocked-uri'],
        violatedDirective: cspReport['violated-directive'],
        originalPolicy: cspReport['original-policy'],
    }); // Log specific details from the violation report
    res.sendStatus(204); // Respond with no content status
});

app.get("/createPost", (req, res) => {
    if (req.session.username) {
        const message = req.query.message || "";
        res.render("create_post.ejs", { message });
    } else {
        res.redirect("/login");
    }
});

app.get("/", (req, res) => {
    const referer = req.get('Referer');
    if (req.session.admin) {
        try {
            const logs = getAllDecryptedLogs();
            res.render("main_admin.ejs", { log: JSON.stringify(logs, null, 2), data: req.session });
        } catch (error) {
            console.error("Error retrieving logs:", error);
            res.redirect("/login?message=Error retrieving logs");
        }
    } else if (req.session.username) {
        res.render("main.ejs", { data: req.session });
    } else {
        res.redirect("/login");
    }
});

app.get("/login", (req, res) => {
    if (req.session.username) {
        res.redirect("/");
    } else {
        res.render("login.ejs", { message: req.query.message || "", success: req.query.success || "" });
    }
});

app.get("/generateKeypair", (req, res) => {
    res.render("generate_keypair");
});



app.get("/voteContent", (req, res) => {
    if (!req.session.username) {
        res.redirect("/login");
        return;
    }
    
    const { type = "", vote = "", id = "", post_id = "" } = req.query;
    
    if (!type || !vote || !id || !post_id) {
        res.redirect("/forum?message=an+error+occured");
        return;
    }
    
    const result = voteContent(id, req.session.user_id, vote, type);
    if (!result) {
        res.redirect("/forum?message=Youve+already+voted+on+that+piece+of+content.");
    } else {
        res.redirect(`/post?id=${post_id}`);
    }
});

app.get("/forum", async (req, res) => {
    if (!req.session.username) {
        res.redirect("/login");
        return;
    }
    
    const topic_id = req.query.topic_id || 0;
    const order = req.query.order || "desc_aura";
    const message = req.query.message || "";
    const message_success = req.query.message_success || "";
    
    try {
        const posts_from_db = await getPosts(topic_id, order);
        const posts_to_render = posts_from_db.map(post => {
            const decryptedTitle = decrypt(post.title);
            const decryptedTags = decrypt(post.tags);
            const decryptedContent = decrypt(post.content);
            const encryptedUsername = getUsernameById(post.user_id);
            const decryptedUsername = decrypt(encryptedUsername);
            return {
                id: post.id,
                title: decryptedTitle,
                username: decryptedUsername,
                time_created: post.time_created,
                aura: post.aura
            };
        });
        res.render("forum.ejs", { posts: posts_to_render, message, message_success });
    } catch (error) {
        console.error("Error retrieving posts:", error);
        res.redirect("/forum?message=Error retrieving posts");
    }
});

app.post("/executeCreatePost", async (req, res) => {
    if (!req.session.username) {
        res.redirect("/login");
        return;
    }
    const captcha = await checkCaptcha(req)
    if (!captcha) return res.redirect("/forum?message=Incorrect or expired captcha");
    
    const { title = "", content = "", topic = "", tags = "" } = req.body;

    if (!title || !content || !topic || !tags) {
        res.redirect("/forum?message=an+error+occured.");
        return;
    }
    
    try {
        createPost(title, topic, req.session.user_id, content, tags);
        res.redirect("/forum?message_success=created+successfully");
    } catch (error) {
        console.error("Error creating post:", error);
        res.redirect("/forum?message=an+error+occured");
    }
});

app.get("/join_private_room", (req, res) => {
    if (req.session.username) {
        res.render("join_private_room.ejs");
    } else {
        res.redirect("/login");
    }
});

// Chat room selection
app.get("/chat_main", async (req, res) => {
    if (!req.session.username) {
        res.redirect("/login");
        return;
    }

    try {
        const rooms = await getRooms();
        const roomsToRender = rooms
            .filter(room => room.password === "")
            .map(room => ({ title: decrypt(room.title), id: room.id }));
        
        res.render("chat_main.ejs", { rooms: roomsToRender, message: req.query.message || "" });
    } catch (error) {
        console.error("Error retrieving chat rooms:", error);
        res.redirect("/chat_main?message=Error retrieving chat rooms");
    }
});

app.get("/room_help", (req, res) => {
    res.render("room_help.ejs");
});

app.get("/vendorship", (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }
    if (req.session.vendor) {
        return res.render("vendor_main")
    } 
    res.render("vendorship_info")
});

app.get("/vendorshipRegister", (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }
    if (req.session.vendor) {
        return res.redirect("/vendorship");
    }
    const aura = getAuraById(req.session.user_id);
    
    res.render("vendorship_register");
});

app.post("/executeVendorshipRegister", async (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }
    if (req.session.vendor) {
        return res.redirect("/vendorship");
    }
    const captcha = await checkCaptcha(req)
    if (!captcha) return res.redirect("/error?message=Incorrect or expired captcha")
    const aura = getAuraById(req.session.user_id);
    const { vendor_name, about, email, tags } = req.body;
    if (!isItReal(vendor_name) || !isItReal(about) || !isItReal(email) || !isItReal(tags)) return res.redirect("/vendorshipRegister");
    createVendorship(req.session.user_id, about, email, tags, vendor_name);
    return res.redirect("/confirmVendorship");
});

app.get("/confirmVendorship", (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    } 
    res.render("confirm_vendorship");
});

app.get("/myProducts", (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }
    if (!req.session.vendor) {
        return res.redirect("/vendorship");
    }
    const products = getProducts(req.session.vendor_id);
    let renderProducts = [];
    for (let product of products) {
        const decryptedDescription = decrypt(product.description);
        const decryptedPrice = decrypt(product.price);
        const decryptedNotes = decrypt(product.notes);
        const decryptedName = decrypt(product.name);
        const image = isItReal(product.image) ? decrypt(product.image) : 0;
        renderProducts.push({description: decryptedDescription, name: decryptedName, price: decryptedPrice, notes: decryptedNotes, id: product.id, vendor_id: product.vendor_id, image: image});
    }
    return res.render("my_products", {products: renderProducts}); 
});

app.get("/createProduct", (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }
    if (!req.session.vendor) {
        return res.redirect("/vendorship");
    }
    res.render("create_product", {message: req.query.message  ? req.query.message : ""});
});

app.post("/executeCreateProduct", upload.single('image'), async (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }
    if (!req.session.vendor) {
        return res.redirect("/vendorship");
    }
    const captcha = await checkCaptcha(req)
    if (!captcha) res.redirect("/createProduct?message=Incorrect or expired captcha");
    const { name, description, price, tags, notes, system_price, address, system_payments } = req.body;
    if (!isItReal(name) || !isItReal(description) || !isItReal(price) || !isItReal(tags) || !isItReal(notes)) {
        return res.redirect("/createProduct");
    }
    if (system_payments) {
        if (!isItReal(system_price) || !isItReal(address)) {
            return res.redirect("/createProduct");
        }
    }
    let image;
    if (req.file) {
        // Convert uploaded file buffer to Base64
        image = req.file.buffer.toString('base64');
    } else {
        fs.readFile("public/images/default_product.png", (err, data) => {
            if (err) {
                console.error('Error reading the file:', err);
                return;
            }
            // Convert to Base64
            const base64String = data.toString('base64');
            image = base64String;
        });
    }
    try {
        const result = await createProduct(req.session.vendor_id, name, description, price, tags, notes, image, system_price, address, system_payments);

    } catch (e) {
        logger.error("Error creating a product: " + e)
    }

    //console.log(result)
    const productData = await getProductData(req.session.vendor_id, name);
    
    const id = productData ? productData.id : res.redirect("/createProduct?message=an error occured")
    res.redirect("/product?product_id="+id)
});



app.get("/product", (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }

    const product_id = req.query.product_id ? req.query.product_id : "";
    if (!isItReal(product_id)) return res.redirect("/");

    const productData = getProductDataById(product_id);
    const stringProductData = JSON.stringify(productData);
    const decryptedDescription = decrypt(productData.description);
    const decryptedPrice = decrypt(productData.price);
    const decryptedName = decrypt(productData.name);
    const decryptedImage = productData.image ? decrypt(productData.image) : "";
    const decryptedReviews = isItReal(productData.reviews) ? decrypt(productData.reveiws) : [];
    const decryptedBuys = (productData.buys != 0) ? decrypt(productData.buys) : 0;
    const decryptedTags = decrypt(productData.tags);
    const decryptedNotes = decrypt(productData.notes);
    const systemPayments = productData.system_payments;
    const created_time = productData.created_time;

    const vendor = getVendorData(productData.vendor_id);
    let vendorName;
    if (vendor) {
        vendorName = decrypt(vendor.vendor_name);
    } else {
        return res.redirect("error", {message: "the product you requested didn't seem to have an owner. :("});
    }


    let renderReviews = [];
    for (let review of decryptedReviews) {
        // "username1!content1!time1*username2!content2!time2"
        const reviewUsername = review.split("!")[0];
        const reviewContent = review.split("!")[1];
        const reviewTime = review.split("!")[2];
        renderReviews.push({username: reviewUsername, content: reviewContent, created_time: reviewTime});
    }
    
    res.render("product", {id: productData.id, vendor_id: productData.vendor_id, vendor_name: vendorName, created_time: created_time, description: decryptedDescription, price: decryptedPrice, name: decryptedName, image: decryptedImage, reviews: renderReviews, buys: decryptedBuys, tags: decryptedTags, notes: decryptedNotes, system_payments: systemPayments});
});

app.get("/editProduct", (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }
    if (!req.session.vendor) {
        return res.redirect("/vendorship");
    }

    const product_id = req.query.product_id;

    const productData = getProductDataById(product_id);

    const decryptedDescription = decrypt(productData.description);
    const decryptedPrice = decrypt(productData.price);
    const decryptedName = decrypt(productData.name);
    const decryptedImage = decrypt(productData.image);
    const decryptedReviews = isItReal(productData.reviews) ? decrypt(productData.reveiws) : [];
    const decryptedBuys = (productData.buys != 0) ? decrypt(productData.buys) : 0;
    const decryptedTags = decrypt(productData.tags);
    const decryptedNotes = decrypt(productData.notes);
    const systemPayments = productData.system_payments;
    const created_time = productData.created_time;
    const decryptedAddress = isItReal(productData.address) ? decrypt(productData.address) : "";
    const decryptedSystemPrice = decrypt(productData.system_price);

    res.render('edit_product', {
        id: productData.id,
        vendor_id: productData.vendor_id,
        vendor_name: productData.vendor_name,
        name: decryptedName,
        description: decryptedDescription,
        price: decryptedPrice,
        system_price: decryptedSystemPrice,
        system_payments: systemPayments,
        notes: decryptedNotes,
        image: decryptedImage,
        address: decryptedAddress,
        tags: decryptedTags,
        buys: decryptedBuys,
        created_time: created_time,
        reviews: decryptedReviews
    }); 
});




app.get("/info", (req, res) => {
    res.render("info", {message: req.query.message ? req.query.message : "No info"})
})

app.get("/error", (req, res) => {
    res.render("error", {message: req.query.message ? req.query.message : "No error message"})
})

app.get("/vendorSettings", (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }
    if (!req.session.vendor) {
        return res.redirect("/vendorship");
    }
    const vendor_id = req.session.vendor_id;
    const vendorData = getVendorData(vendor_id);
    const vendor_name = isItReal(vendorData.vendor_name) ? decrypt(vendorData.vendor_name) : res.redirect("/error?message=An error has occured with your vendorship. Please contact an administrator.");
    const email = isItReal(vendorData.email) ? decrypt(vendorData.email) : "";
    const about = isItReal(vendorData.about) ? decrypt(vendorData.about) : "";
    const tags = isItReal(vendorData.tags) ? decrypt(vendorData.tags) : "";
    const created_at = vendorData.created_at;

    return res.render("vendor_settings", {vendor_name, email, about, tags, created_at});
});

app.post("/updateVendorSettings", (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }
    if (!req.session.vendor) {
        return res.redirect("/vendorship");
    }
    const { vendor_name, email, about, tags } = req.body;
    updateVendorSettings(req.session.vendor_id, vendor_name, email, about, tags);
    res.redirect("/vendorSettings");
})



// Chat room access handling
app.get("/chatroom", async (req, res) => {
    if (!req.session.username) {
        res.redirect("/login");
        return;
    }
    
    const room_id = req.query.room_id || await getRoomData(req.query.room_title)?.id;
    
    if (!room_id) {
        return res.redirect("/chat_main");
    }

    try {
        const roomData = getRoomData(room_id);
        const room_title = decrypt(roomData.title);

        if (roomData.password) {
            if (req.session.authedRooms.includes(room_title)) {
                const public_key = decrypt(getPublicKey(req.session.user_id));
                res.render("chatroom.ejs", { room_id, room_title, sender_public_key: public_key, sender_id: req.session.user_id });
            } else {
                res.redirect(`/roomLogin?room_id=${room_id}&room_title=${room_title}`);
            }
        } else {
            res.render("chatroom.ejs", { room_id, room_title, sender_id: req.session.user_id, sender_public_key: decrypt(getPublicKey(req.session.user_id)) });
        }
    } catch (error) {
        console.error("Error accessing chat room:", error);
        res.redirect("/chat_main?message=Error accessing chat room");
    }
});

app.get("/profile", (req, res) => {
    if (req.session.username) {
        const userData = getUser(req.query.user_id) ? getUser(req.query.user_id) : res.redirect("/");
        const user_id = req.query.user_id;
        const username = decrypt(userData.username);
        const aura = userData.aura;
        const created_at = userData.created_at;
        const admin = userData.admin;
        const public_key = decrypt(userData.public_key);
        const about = isItReal(userData.about) ? decrypt(userData.about) : "";
        const global = userData.global; // Will he show up on global discovery list
        const pfp = userData.pfp;
        const tags = isItReal(userData.tags) ? decrypt(userData.tags) : "";
        const email =  isItReal(userData.email) ? decrypt(userData.email) : "";

        res.render("profile", {username, aura, created_at, admin, public_key, about, global, pfp, tags, email, user_id})
    } else {
        res.redirect("/login");
    }
});

app.get("/account", (req, res) => {
    if (req.session.username) {
        const userData = getUser(req.session.user_id);

        const username = decrypt(userData.username);
        const aura = userData.aura;
        const created_at = userData.created_at;
        const last_paid = userData.last_paid;
        const admin = userData.admin;
        const public_key = decrypt(userData.public_key);
        const about = isItReal(userData.about) ? decrypt(userData.about) : "";
        const global = userData.global; // Will he show up on global discovery list
        const pfp = userData.pfp;
        const tags = isItReal(userData.tags) ? decrypt(userData.tags) : "";
        const email =  isItReal(userData.email) ? decrypt(userData.email) : "";


        res.render("account", {username, aura, created_at, admin, last_paid, public_key, about, global, pfp, tags, email})
    } else {
        res.redirect("/login");
    }
})


app.get("/placeOrder", (req, res) => {
    if (!req.session.username) return res.redirect("/login");
    const { product_id, amount } = req.query;
    for (let i=0; i<orders.length; i++) {
        if (orders[i].session_id == req.session.id) return res.redirect("/error?message=Um you already have a pending order. Wait like 5 mins for it to clear out and then try again i guess");
    }
    if (!(isItReal(product_id) && isItReal(amount))) {
        const address = generateNewAddress();
        const product = getProductDataById(product_id);
        const system_price = product.system_price;
        const expected_price_USD = system_price * amount;
        const expected_price_BTC = convertUsdToBtc(expected_price_USD);
        const pending_order_uuid = generateUUID(); // We use a dict because 1) we can check the existence of a uuid in o(1) time, and 2) can reference pending orders and keep track of them from outside of the server
        ordersPending[pending_order_uuid] = {time: Date.now(), address: address, session_id: req.session.id, product_id: product_id, amount: amount, expected: expected_price_BTC};
        res.redirect("/orderPending?uuid="+pending_order_uuid);
    } 
});

app.get("/orderPending", async (req, res) => {
    if (!req.session) res.redirect("/login");
    const { uuid } = req.query;
    if (!isItReal(uuid)) return res.redirect("/error?message=this shouldnt happen, unless you did something manually or the server broke. try again pls or lmk!");
    const order_in_question = ordersPending[uuid];
    if (order_in_question && order_in_question.session_id == req.session.id) { // Check if such order exists, and then if it belongs to the guy in question
        const amount_recieved = await getTotalReceivedByAddress(order_in_question.address);
        if (amount_recieved >= order_in_question.expected) {
            const product = getProductDataById(order_in_question.product_id);
            // now, get the data abt the product, create the product, and then make a 
            // product_id, user_id, amount, vendor_id, estimated_arrival
            createOrder(product.id, order_in_question.user_id, order_in_question.amount, product.vendor_id, "1/1/1975");
            return res.redirect("/orderComplete");
        } else {
            return res.render("order_pending", {address, uuid, amount_recieved, amount_expected: expected});
        }
    } else {
        // Order doesnt exist. We say so
        const problem_order_uuid = await generateUUID();
        logger.warn("Hey! An order that didnt exist (timed out?) was attempted to be accessed. The problem order uuid was "+problem_payment_uuid+" .")
        return res.redirect("/error?message=hm. this order doesnt seem to exist. It is possible that the order timed out (the payment didn't go through in time). Please try again. <br> IF YOU PAYED MONEY ALREADY AND IT DID THIS PROBLEM: your id is "+problem_payment_uuid+" . Save this.  Also save the BTC address to which you paid the money. Contact me with it and we will work something out.")
    }
});

app.get("/orderComplete", (req, res) => {
    const { uuid } = req.query;
    if (!req.session) res.redirect("/login");
    const order_in_question = ordersPending[uuid];
    if (order_in_question && order_in_question.session_id == req.session.id) {
        delete ordersPending[uuid];
        return res.render("order_complete");
    }
    res.render("order_incomplete");
});


app.get('/createOrder', (req, res) => {
    if (!req.session.username) return res.redirect("/login");
    const product_id = req.query.product_id;
    if (!product_id) return res.redirect("/error?message=Please go back and pick a valid product id");
    const product = getProductDataById(product_id);
    const product_decrypted = {
        description: decrypt(product.description),
        price: decrypt(product.price),
        notes: decrypt(product.notes),
        name: decrypt(product.name),
        image: decrypt(product.image),
        system_price: system_price
    };
    
    res.render("create_order", {product: product_decrypted, message:req.query.message?req.query.message : ""});
});

// app.post('/executeCreateOrder', async (req, res) => {
//     if (!req.session.username) return res.redirect("/login");
//     const captcha = await checkCaptcha(req);
//     if (!captcha) return res.redirect("/createOrder?message=Incorrect or expired captcha");
//     const { amount, product_id }
// })


app.post('/updateAccount', upload.single('pfp'), (req, res) => {
    if (req.session.username) {
        const { username, email, tags, about, global, user_id, public_key, pfp } = req.body;
        if (username == "" || global == "" || public_key == "" || pfp == "") {
            res.redirect("/account");
        }
        const encryptedEmail = encrypt(email);
        const encryptedTags = encrypt(tags);
        const encryptedAbout = encrypt(about);
        const encryptedPublicKey = encrypt(public_key);
        const encryptedUsername = encrypt(username);
        let newpfp;
        if (req.file) {
            // Convert uploaded file buffer to Base64
            newpfp = req.file.buffer.toString('base64');
        } else {
            newpfp = req.session.pfp;
        }
    
        //console.log(encryptedEmail, encryptedTags, encryptedAbout, encryptedUsername, newpfp)
    
        const stmt = db.prepare(`UPDATE users SET username = ?, email = ?, tags = ?, about = ?, global = ?, public_key = ?, pfp = ? WHERE id = ?`);
        stmt.run(encryptedUsername, encryptedEmail, encryptedTags, encryptedAbout, global, encryptedPublicKey, newpfp, req.session.user_id)
        res.redirect("/account"); 
    } else {
        res.redirect("/login");
    }

});

app.post('/updateProduct', upload.single('image'), (req, res) => {
    if (req.session.username) {
        // Get form data
        const { name, description, price, system_price, system_payments, notes, address, tags, product_id } = req.body;

        // Validation checks: Make sure required fields are not empty
        if (!isItReal(name) || !isItReal(description) || !isItReal(price) || !isItReal(tags)) {
            return res.status(400).send('Required fields (name, description, price, tags) are missing.');
        }

        // Ensure system_price is a valid number if provided
        if (system_price && isNaN(system_price)) {
            return res.status(400).send('System price must be a valid number.');
        }

        // Encrypt the data from the form
        const encryptedDescription = encrypt(description);
        const encryptedPrice = encrypt(price);
        const encryptedName = encrypt(name);
        const encryptedTags = encrypt(tags);
        const encryptedNotes = encrypt(notes);
        const encryptedAddress = encrypt(address);
        const encryptedSystemPrice = system_price ? encrypt(system_price) : null;
        const encryptedSystemPayments = system_payments ? 1 : 0;

        // Handle image data (use uploaded image if available, otherwise retain the old image)
        const encryptedImage = req.file ? req.file.buffer.toString('base64') : null;

        // Prepare the update query
        const stmt = db.prepare(`
            UPDATE catalogue SET
                name = ?, description = ?, price = ?, system_price = ?, system_payments = ?, 
                notes = ?, address = ?, tags = ?, image = ?
            WHERE id = ?
        `);

        // Run the query and check for errors
        try {
            stmt.run(
                encryptedName, encryptedDescription, encryptedPrice, encryptedSystemPrice, encryptedSystemPayments,
                encryptedNotes, encryptedAddress, encryptedTags, encryptedImage, product_id
            );
            
            // After successfully running the query, redirect to the updated product page
            res.redirect(`/product?product_id=${product_id}`);
        } catch (err) {
            // Log and handle database errors
            console.error('Error updating product:', err.message);
            res.status(500).send('An error occurred while updating the product.');
        }
    } else {
        // Redirect to login if no session found
        res.redirect("/login");
    }
});

app.get("/vendor", async (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login")
    }
    let vendor_id;
    if (req.query.vendor_id) {
        vendor_id = req.query.vendor_id;
    } else {
        return res.redirect("/");
    }
    const vendorInfo = getVendorData(vendor_id);
    const decryptedAbout = decrypt(vendorInfo.about);
    const decryptedEmail = decrypt(vendorInfo.email);
    const decryptedTags = decrypt(vendorInfo.tags);
    const decryptedName = decrypt(vendorInfo.vendor_name);
    const created_at = vendorInfo.created_at;
    const user_id = vendorInfo.user_id;
    const userAura = await getAuraById(user_id);
    const renderVendor = {
        name: decryptedName,
        about: decryptedAbout,
        email: decryptedEmail,
        tags: decryptedTags,
        created_at: created_at,
        user_id: user_id,
        aura: userAura
    }
    const products = getProducts(vendor_id);
    let renderProducts = [];
    for (let product of products) {
        const decryptedName = decrypt(product.name);
        const decryptedTags = decrypt(product.tags);
        const decryptedImage = product.image ? decrypt(product.image) : "";
        const decryptedPrice = decrypt(product.price);
        const decryptedBuys = product.buys != "0" && product.buys != 0 ? decrypt(product.buys) : "1";
        const productData = {
            name: decryptedName,
            tags: decryptedTags,
            id: product.id,
            image: decryptedImage,
            price: decryptedPrice,
            buys: decryptedBuys
        }
        renderProducts.push(productData);
    }
    
    res.render("vendor_info", {renderVendor, renderProducts})
});


app.get("/marketplace", (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }
    let products = []
    const acceptableParameters = {aura: ["asc, desc"]}
    const sort_method = req.query.sort_method ? req.query.sort_method : "default";
    const sort_parameter = req.query.sort_parameter ? req.query.sort_parameter : "default";

    switch (sort_method){
        case "default":
            products = getProductsByBuys();
            break;
        case "name":
            let product_names = product_names_tree.getPrefix(sort_parameter)
            for (let name of product_names) {
                products.push(name_product_dict[name]);
            }
            break;
        case "tags_all":
            if (!isItReal(sort_parameter)) return res.redirect("/marketplace")
            products = searchTagsAND(sort_parameter);
            break;
        case "tags_or":
            if (!isItReal(sort_parameter)) return res.redirect("/marketplace");
            products = searchTagsOR(sort_parameter);
            break;
        default:
            return res.redirect("/marketplace");
    }

    let renderProducts = [];
    for (let product of products) {
        const decryptedName = decrypt(product.name);
        const decryptedPrice = decrypt(product.price);
        const buys = product.buys;
        const decryptedTags = decrypt(product.tags);
        const system_payments = product.system_payments;
        const decryptedImage = decrypt(product.image);
        const productData = {
            name: decryptedName,
            price: decryptedPrice,
            buys: buys,
            tags: decryptedTags,
            system_payments: system_payments,
            image: decryptedImage,
            id: product.id
        }
        renderProducts.push(productData);
    }

    res.render("marketplace", {
        products: renderProducts,
        message: req.query.message || "",
        message_success: req.query.message_success || "",
        sort_method: sort_method,
        sort_parameter: sort_parameter
    });
});


app.get("/deleteConversation", (req, res) => {
    if (req.session.username) {
        const receiver_id = req.query.user_id;
        let users;
        if (receiver_id > req.session.user_id) {
            users = `${receiver_id},${req.session.user_id}`;
        } else {
            users = `${req.session.user_id},${receiver_id}`;
        }
        deleteConversation(users);
        res.redirect("/directMessagesMain");
    } else {
        res.redirect("/login");
    }
});


// Password check for private chat rooms
app.get("/roomLogin", (req, res) => {
    if (req.session.username) {
        const room_id = req.query.room_id || res.redirect("/chat_main");
        const room_title = req.query.room_title || res.redirect("/chat_main");

        const authToken = crypto.randomBytes(32).toString('hex');
        req.session.authToken = authToken;
        validAuthTokens.push(authToken);

        res.render("chatroom_password.ejs", { room_id, room_title });
    } else {
        res.redirect("/login");
    }
});

// Execute room login with password
app.post("/executeRoomLogin", async (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }
    const captcha = await checkCaptcha(req);
    if (!captcha) res.redirect("/chat_main?message=Incorrect or expired captcha")

    if (!req.session.authToken || !validAuthTokens.includes(req.session.authToken)) {
        return res.redirect("/login");
    }

    req.session.authToken = null;

    const room_title = req.body.room_title || res.redirect("/chat_main");
    const room_id = req.body.room_id || res.redirect("/chat_main");
    const request_password = req.body.password;

    if (!request_password) {
        return res.redirect(`/middlemanRoom?destination=${encodeURIComponent("/roomLogin")}`);
    }

    try {
        const roomData = getRoomData(room_id);
        const hashedRequestPassword = await hashPassword(request_password);

        if (decrypt(roomData.password) === hashedRequestPassword) {
            req.session.authedRooms.push(room_title);
            res.redirect(`/middlemanRoom?destination=${encodeURIComponent(`/chatroom?room_id=${room_id}`)}`);
        } else {
            res.redirect(req.get('Referer'));
        }
    } catch (error) {
        console.error("Error executing room login:", error);
        res.redirect("/chat_main?message=Error logging in to room");
    }
});

app.get("/save_private_key_to_localstorage", (req, res) => {
    res.render("save_private_key");
});

app.post("/executeCreateAccount", upload.single('pfp_'), async (req, res) => {
    if (!req.session.username) {
        const captcha = await checkCaptcha(req)
        if (!captcha) return res.redirect("/createAccount?message=incorrect or expired captcha");
        const { username, password, password1, email, tags, about, public_key, global_bool } = req.body;
        if (username == "" || password == "" || public_key == "") {
            res.redirect("/createAccount?message=You missed a piece");
            return;
        }
        if (password != password1) {
            res.redirect("/createAccount?message=Your passwords don't match");
            return;
        }

        let newpfp;
        if (req.file) {
            // Convert uploaded file buffer to Base64
            newpfp = req.file.buffer.toString('base64');
        } else {
            fs.readFile("public/images/image.png", (err, data) => {
                if (err) {
                    console.error('Error reading the file:', err);
                    return;
                }

                // Convert to Base64
                const base64String = data.toString('base64');
                newpfp = base64String;
            });
        }
        await createUser(username, password, 0, about, public_key, global_bool, newpfp, tags, email);
        res.redirect("/login?success=please log in with your new account!!");
    } else {
        res.redirect("/")
    }
});

app.get("/createAccount", (req, res) => {
    if (!req.session.username) {
        res.render("create_account");
    } else {
        res.redirect("/login?message=youre already logged in. If you see this, something broke. Contact me.");
    }
})

app.get("/globalUsers",async  (req, res) => {
 if (req.session.username) {
    const users_ = await getUsers();
    let renderUsers = [];
    for (let user of users_) {
        if (user.global) {
            const username = decrypt(user.username);
            const aura = user.aura
            const tags = isItReal(user.tags) ? decrypt(user.tags) : "";
            const id = user.id
            renderUsers.push({username, aura, tags, id});
        }
    }
    res.render("global_users_list", {users: renderUsers});
    return;
 }
 res.redirect("/login");
 
})

app.get("/middlemanRoom", (req, res) => {
    res.redirect(req.query.destination || "/login");
});

app.get("/directMessagesMain", async (req, res) => {
    if (req.session.username) {

        const users = await getUsersForDMs(req.session.user_id);
        res.render("direct_messages_main", { user_id: req.session.user_id, users});
    } else {
        res.redirect("/login");
    }
});

app.get("/goToDirectMessages", (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }

    const receiver_user_id = req.query.username ? usernameToId[req.query.username] : req.query.user_id || res.redirect("/directMessagesMain");
    
    if (!receiver_user_id) {
        return res.redirect("/directMessagesMain");
    }
    
    res.redirect("/directMessagesChat?user_id=" + receiver_user_id);
});

app.get("/post", async (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }

    const id = req.query.id || "";
    const comments_sort = req.query.comments_sort || "aura_desc";

    if (id === "") {
        return res.redirect("/forum?message=please+select+a+post+to+view");
    }

    try {
        const post = getPostById(id);
        const decryptedContent = decrypt(post.content);
        const decryptedUsername = decrypt(getUsernameById(post.user_id));
        const decryptedTitle = decrypt(post.title);
        
        const post_to_render = {
            id: post.id,
            content: decryptedContent,
            username: decryptedUsername,
            title: decryptedTitle,
            aura: post.aura,
            created_time: post.created_time
        };
        const poster_data = getUser(post.user_id);
        const poster_pfp = poster_data.pfp;
        const comments_for_post = await getComments(id, comments_sort);
        const comments_to_render = await Promise.all(comments_for_post.map(async comment => {
            const decryptedContentComment = decrypt(comment.content);
            const user = await getUser(comment.user_id); // Get user data using user_id
            const decryptedUsernameComment = decrypt(user.username); // Assuming username is part of user data
            const pfp = user.pfp; // Assuming pfp is part of the user data
        
            return {
                id: comment.id,
                content: decryptedContentComment,
                username: decryptedUsernameComment,
                pfp: pfp, // Add pfp to the comment object
                aura: comment.aura,
                created_time: comment.created_at
            };
        }));

        res.render("post.ejs", { post: post_to_render, comments: comments_to_render, pfp: poster_pfp});
    } catch (error) {
        console.error("Error retrieving post:", error);
        res.redirect("/forum?message=Error retrieving post");
    }
});

app.get("/chathelp", (req, res) => {
    res.render("chat_help.ejs");
});

app.post("/postComment", (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }

    const { content = "", post_id = "" } = req.body;

    if (!content || !post_id) {
        return res.redirect(`/post?id=${post_id}&message=Error posting comment`);
    }

    try {
        createComment(post_id, req.session.user_id, content);
        res.redirect("/post?id=" + post_id);
    } catch (error) {
        console.error("Error posting comment:", error);
        res.redirect(`/post?id=${post_id}&message=Error posting comment`);
    }
});

app.get("/security", (req, res) => {
    res.render("security.ejs");
});

app.get("/directMessagesChat", (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }

    const receiver_id = req.query.user_id;

    if (!receiver_id) {
        return res.redirect("/directMessagesMain");
    }

    const sender_id = req.session.user_id;
    const sender_username = getUsernameById(sender_id);
    const receiver_public_key = getPublicKey(receiver_id);
    const sender_public_key = getPublicKey(sender_id);

    const decrypted_receiver_public_key = receiver_public_key !== -1 ? decrypt(receiver_public_key) : "This user does not exist, or does not have a public key associated with their account. Try again.";
    const decrypted_sender_public_key = sender_public_key !== -1 ? decrypt(sender_public_key) : "You don't exist or don't have a public key associated with your account. Try again.";

    const data = {
        receiver_id,
        sender_id,
        sender_username,
        receiver_public_key: decrypted_receiver_public_key,
        sender_public_key: decrypted_sender_public_key
    };
    
    res.render("direct_messages_chat", data);
});

app.get("/createRoom", (req, res) => {
    if (req.session.username) {
        res.render("create_room.ejs");
    } else {
        res.redirect("/login");
    }
});

app.post("/executeCreateRoom", async (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }
    const captcha = await checkCaptcha(req);
    if(!captcha) res.redirect("/createRoom?message=Incorrect or expired captcha")

    const room_title = req.body.room_title || res.redirect("/createRoom");
    const password = req.body.password || "";
    const locked = req.body.locked ? 1 : 0;

    try {
        const id = await createRoom(room_title, password, locked);
        res.redirect("/chat_main?message=success: your room id is " + id);
    } catch (error) {
        console.error("Error creating room:", error);
        res.redirect("/createRoom?message=Error creating room");
    }
});

app.post("/executeLogin", async (req, res) => {
    const { username: request_username = "", password: request_password = "" } = req.body;

    if (!request_username || !request_password) {
        return res.redirect("/login?message=Please+provide+username+and+password");
    }
    const captcha = await checkCaptcha(req)
    if (!captcha) return res.redirect("/login?message=Incorrect or expired captcha")

    try {
        const users_database = await getUsers();
        for (const user_database of users_database) {
            const result = await bcrypt.compare(request_password, decrypt(user_database.password));
            if (decrypt(user_database.username) === request_username && result) {
                req.session.username = request_username;
                req.session.admin = user_database.admin;
                req.session.last_paid = user_database.last_paid;
                req.session.user_id = user_database.id;
                req.session.authedRooms = [];
                req.session.pfp = user_database.pfp;
                
                if (user_database.vendor_id != null) {
                    req.session.vendor = true;
                    req.session.vendor_id = user_database.vendor_id;
                } // make sure to set the actual user's vendor_id to not null when a vendorship is created. Add data to session. then, test.
                if (req.session.admin) {
                    logger.info(`An admin logged in - ${req.session.username}`);
                }
                return res.redirect(req.get("Referrer") || "/");
            }
        }
        res.redirect("/login?message=incorrect");
    } catch (error) {
        console.error("Error during login:", error);
        res.redirect("/login?message=Error during login");
    }
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/login");
});

// Admin routes

app.get("/deleteRoom", (req, res) => {
    if (req.session.admin) {
        res.render("delete_room");
    } else {
        res.redirect("/");
    }
});

app.post("/executeDeleteRoom", (req, res) => {
    if (!req.session.admin) {
        return res.redirect("/");
    }

    const room_title = req.body.room_title || "";
    const room_id = room_title ? roomNameToId[room_title] : req.body.room_id || res.redirect("/chat_main");

    if (!room_id) {
        return res.redirect("/chat_main?message=Invalid room ID");
    }

    try {
        deleteRoom(room_id);
        res.redirect("/chat_main?message=Deleted successfully");
    } catch (error) {
        console.error("Error deleting room:", error);
        res.redirect("/chat_main?message=Error deleting room");
    }
});










io.on('connection', (socket) => {
    logger.debug('New client connected');
    const session = socket.handshake.session; // Access session data

    socket.on('establishment', async (data) => {
        try {
            const sender_id = data.sender_id;
            if (session.username && (session.user_id == sender_id)) {
                const receiver_id = data.receiver_id;
                const receiver_username = decrypt(getUsernameById(receiver_id));

                const users = receiver_id > sender_id ? `${receiver_id},${sender_id}` : `${sender_id},${receiver_id}`;

                const messages = await getMessages(users);
                const renderMessages = messages.map((message) => ({
                    sender_content: decrypt(message.sender_content),
                    receiver_content: decrypt(message.receiver_content),
                    sender_id: message.user_id_from,
                    receiver_id: message.user_id_to,
                    signature: decrypt(message.signature),
                }));

                socket.join(users);
                session.room = users;
                socket.emit("establishment", { receiver_username, messages: renderMessages });
            } else {
                socket.emit("message", { message: "Authentication failed. Please re-login." });
            }
        } catch (error) {
            logger.error("Error in establishment event:", error);
        }
    });

    socket.on('sendMessage', (data = { sender_id: "" }) => {
        try {
            if (session.username && session.user_id == data.sender_id) {
                const { sender_content, receiver_content, receiver_id, sender_id, signature, save } = data;

                const users = receiver_id > sender_id ? `${receiver_id},${sender_id}` : `${sender_id},${receiver_id}`;
                
                if (save) {
                    createMessage(sender_id, receiver_id, encrypt(sender_content), encrypt(receiver_content), encrypt(signature));
                }

                io.to(users).emit("newMessage", { receiver_content, signature, sender_id, save });
            }
        } catch (error) {
            logger.error("Error in sendMessage event:", error);
        }
    });

    socket.on("requestKey", async (data) => {
        try {
            if (session.username && session.authedRooms.includes(data.room_id) && data.sender_id == session.user_id) {
                const roomData = await getRoomData(data.room_id);
                if (roomData.locked) return;

                const public_key = getPublicKey(session.user_id);
                const requestToken = crypto.randomBytes(32).toString('hex');
                requestTokens[requestToken] = session.user_id;

                socket.join(`${session.user_id}:${data.room_id}`);
                io.to(roomData.title).emit("requestKeyForward", { public_key, requestToken });
            }
        } catch (error) {
            logger.error("Error in requestKey event:", error);
        }
    });

    socket.on("requestKeyResponse", (data) => {
        try {
            const requestToken = data.requestToken;
            const requester_id = requestTokens[requestToken];
            delete requestTokens[requestToken];

            io.to(`${requester_id}:${data.room_id}`).emit("requestKeyResponseForward", { encryptedKey: data.encryptedKey });
            socket.leave(`${requester_id}:${data.room_id}`);
        } catch (error) {
            logger.error("Error in requestKeyResponse event:", error);
        }
    });

    socket.on("establishmentRoom", (data) => {
        try {
            if (session.username && session.user_id == data.sender_id) {
                const { room_title, room_id } = data;

                if (decrypt(getRoomTitleById(room_id)) !== room_title) return;

                const roomData = getRoomData(room_id);
                if (roomData.password != "" && !session.authedRooms.includes(room_title)) return;

                socket.join(room_title);
                session.room = room_title;

                const messages = getMessagesRoom(roomData.id);
                const renderMessages = messages.map((message) => ({
                    content: decrypt(message.content),
                    sender_id: message.user_id,
                    sender_username: getUsernameById(message.user_id),
                    save: message.save,
                }));

                socket.emit("establishmentRoom", { messages: renderMessages });
            }
        } catch (error) {
            logger.error("Error in establishmentRoom event:", error);
        }
    });

    socket.on("newMessageRoom", (data) => {
        try {
            if (session.username && session.user_id == data.sender_id) {
                const { content, room_id, room_title } = data;

                if (decrypt(getRoomTitleById(room_id)) != room_title) return;
                const roomData = getRoomData(room_id);
                if (roomData.password != "" && !session.authedRooms.includes(room_title))
                if (room_title !== session.room) return;

                if (data.save) {
                    createMessageRoom(room_id, encrypt(content), session.user_id);
                }

                io.to(room_title).emit("newMessage", { content, sender_id: data.sender_id, sender_username: getUsernameById(session.user_id) });
            }
        } catch (error) {
            logger.error("Error in newMessageRoom event:", error);
        }
    });

    socket.on('message', (msg) => {
        try {
            io.emit('message', msg);
        } catch (error) {
            logger.error("Error in message event:", error);
        }
    });

    socket.on('disconnect', () => {
        try {
            logger.info('Client disconnected');
        } catch (error) {
            logger.error("Error during disconnect:", error);
        }
    });
});


/*
admin : admin
-----BEGIN PUBLIC KEY----- MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCm/jQJloYOrbrwJ8JHtNw6lVlN EctXnYeywoCA0fSBHK3tzrz2L5pNLCexNChVVc4lK3vJqhU25wepmbGS9UGlK9MT Wrc6o16nHC9xCx3Z2i9p5ZFf6ci/x4G0ZJ2758J6r5zsG2cYLfFFszHtjaYhGUq+ Nj+sUv3ixZOdtwWTZQIDAQAB -----END PUBLIC KEY-----



-----BEGIN RSA PRIVATE KEY----- MIICWwIBAAKBgQCm/jQJloYOrbrwJ8JHtNw6lVlNEctXnYeywoCA0fSBHK3tzrz2 L5pNLCexNChVVc4lK3vJqhU25wepmbGS9UGlK9MTWrc6o16nHC9xCx3Z2i9p5ZFf 6ci/x4G0ZJ2758J6r5zsG2cYLfFFszHtjaYhGUq+Nj+sUv3ixZOdtwWTZQIDAQAB AoGAbc0vwi4rL3OkO0ypPiT5ubuB4F8W6SE3nJ6viASFVG/bHUaWkPlz59Jktuuo qZOl3GLfHharpFH8g9P/IrYI1tXo/BWA2lct6qOBoD4JxfBtTdrH5kMRYDo6Ys3i qskvVBqUvyKIQ54EwYej6pCemhABbE164TFzXgUwNlVTPQECQQDYwkQ3P57moBCl 47Ri3cV7FPRppa9jZsMUzobuc+EV+0aDbmOe8nhliE34aC0lEYNhYKgyP1sQFcJd c9avSmhRAkEAxTmG+pzkwtmejo5xBW/wSTjWoI2Ow4DuTMnFKeYgO3zXY9qLS2No KeJUHkaQ7TgjTJRYy+bBlm5FwlDNuOZI1QJAXDiS41qrFX4mdx3hAmtOeOZacpRu gYEYIMMZv1wH+N02i/asZdTNio0qdzSDeJDx77068l3oNXi8gBwny96BcQJAKFsH FYy4+m3RFdZrpfMrta/dquiMR9C/8hJvN42RFtsKr7HuQrTKgZeAItnJmeCcyHSq Xr6O6hsSRxqFncnxKQJAJUBLM9pP3OUm+jfpaME65m+g8KFf4QrMputs6zBE29BO XGrCwNP/yR4I+TAKZUS0b1a2iW5XSd/bySbqrwyaHA== -----END RSA PRIVATE KEY-----


user1 : user1
-----BEGIN PUBLIC KEY----- MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHqej2t14/86Ph8Ej6lHAgNPazpj J8Y81Nua1dW9EojONN7jSHcUfnChcQlrl1xRcWUZXq9SMc69XHAV+qgj5A78KdEn rWqTx4Dq3olqowJROMgxYwis8gnyiAx0wJS4PWaE/qS21XjrcS/e3iB/cY13q9gL OO6l3RRv7xvo0fzhAgMBAAE= -----END PUBLIC KEY-----



-----BEGIN RSA PRIVATE KEY----- MIICXAIBAAKBgHqej2t14/86Ph8Ej6lHAgNPazpjJ8Y81Nua1dW9EojONN7jSHcU fnChcQlrl1xRcWUZXq9SMc69XHAV+qgj5A78KdEnrWqTx4Dq3olqowJROMgxYwis 8gnyiAx0wJS4PWaE/qS21XjrcS/e3iB/cY13q9gLOO6l3RRv7xvo0fzhAgMBAAEC gYB5IFamna9auUsSUuwjGNzZLkPLSpXI0uCmCn6/g+ViNOivYK99ykXYtvG1j43W iTFN4FDTOYuwIQjGRD/2hnXKJO9qznnr4x3CrwSu1Z5Fii/1P7UB+LrtBiQ7khmg 7okTbbfH+TSZ998o+DouT9smDVynRfVBYA8Nh/t3GNt+jQJBAL0jXBtlWkN92fa1 +YIwYYQ5BAESiAwLiObdRxC+X5EALXum/TlRqB/fC/uAq8prnu2EHDtCUkZs+TSH r4UVQfcCQQCl92FeHh1Z1r1mQmySIcv+Adg5BVn72cKdvUdMHJxSRCu0Cd6iNHeW XmDl60Gh+i0IM3GiakckyBB65ReNSoHnAkEAnD/i7qr7N7h3YU4SMxA+71meyjgB 9lltHrP86oMrNgG8kWNx3HFt/+5m2r4Arbfc0oEKRZZTm+SYt2HEiZ/3HwJBAJ7U e2M2EMLMZp+5i+vh2jZxj3sqau5CfSS2YsgtTVDRmr2HAIBdE+Fc2wDOPxaDtJr3 mJVlfkZuDI+ANSTrnBsCQHnrsnXMIhNnFraefHByrL7DxNY+r+xWbjeMLwLD4vzd YGuvIUNNz1TWg/R+VHNAhP3fAqrpF1NM2a/sut0we3w= -----END RSA PRIVATE KEY-----
*/

(async () => {
    try {
        // Prompt for password
        const password = await prompt('Enter your password: ');

        // Hash the password and derive encryption key
        const hashedPassword = hashPassword(password);
        encryptionKey = deriveKey(hashedPassword);

        logger.info('Encryption key has been successfully derived.');
    } catch (error) {
        console.error('Error during password prompt or encryption setup:', error);
        process.exit(1); // Exit if there is an error
    }
})().then(() => {
    // Place any code here that depends on `encryptionKey`
    logger.info('Now ready to start the server with encryption key initialized.');
    server.listen(PORT, async () => {
        updateUsernameToId()
        updateRoomToId();
        rePopulateTrieAndDict();

    
        
        // fs.readFile("public/images/logo.png", (err, data) => {
        //     if (err) {
        //         console.error('Error reading the file:', err);
        //         return;
        //     }
        
        //     // Convert to Base64
        //     const base64String = data.toString('base64');
        //     setPfp(1, base64String)
        //     console.log(base64String); // Logs the Base64 string
        // });
        
        //setUserProfilePicture(12, "public/images/logo.png")
        //addPublicKey(11, "-----BEGIN PUBLIC KEY----- MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHBP3NRbSxkemKcre2ZJvGWTpb8b Mkv3LEr3wOet9YLMaCsMPxlL+WTHeKblDAk4QorB6TYMY4JXgyJhOnnv4tfgevJM WWTQfUnE+2qUp/EfQgX4hMq5rYrvmLfUwJ96RrYs3mFraszAY8GahjhXXQFYDbVz 5AZcXM9wiQVycisxAgMBAAE= -----END PUBLIC KEY-----")
    
        //console.log(encrypt("signage"))
        //createRoom("private room", "password");
        //createRoom("private room", "password");
        //getAllDecryptedLogs()
        //createUser('admin', 'admin', 1, "I'm an admin.", "-----BEGIN PUBLIC KEY----- MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHBP3NRbSxkemKcre2ZJvGWTpb8b Mkv3LEr3wOet9YLMaCsMPxlL+WTHeKblDAk4QorB6TYMY4JXgyJhOnnv4tfgevJM WWTQfUnE+2qUp/EfQgX4hMq5rYrvmLfUwJ96RrYs3mFraszAY8GahjhXXQFYDbVz 5AZcXM9wiQVycisxAgMBAAE= -----END PUBLIC KEY-----", 1, "", "admin, tag1", "admin@admin.com");
        
        //createTopic("General");
        //createPost("Test Post!: 2", 1, 3, "This is the content of the second post.", "general, discussion");
        //createComment(1, 3, "Test Comment!");
        //createComment(1, 3, "Test Comment: 2!");
        // const hash = await bcrypt.hash("message", 10)
        // console.log(hash);
        // const result = await bcrypt.compare("user2", "$2b$10$wOKHR84iKgwf49OAVx0WueWb.EmvCzZtoEm2s8Wu9A.nQhfoXn82e")
        // console.log(result)
        // console.log(decrypt("c87c7de12925ae75891569dc8d5d516b69ba99cd2f74781943b98cf60ee318a733dde41e6661708422d7ba42b274e0bf7c4891709b5b0a9fc3db0b75383df8d963bc051b9e2eab24ceafa3c1fb0ae44a"))
        
        logger.info("Listening on port " + PORT);
    });
});




















/*
TODO:

vendor page - listings
main page - listings
review system
buying system


*/