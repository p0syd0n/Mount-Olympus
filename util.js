import readline from 'readline';
import crypto from 'crypto';

export function prompt(question) {
    return new Promise((resolve) => {
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        // Ask the question
        rl.question(question, (answer) => {
            resolve(answer);  // Resolve the promise with the answer
            rl.close();  // Close the readline interface
        });
    });
}

// Function to derive an encryption key from the hashed password
export function deriveKey(hashedPassword) {
    // You can use a unique salt if necessary
    const salt = 'pepper#$@I)(U$)U@)$#JFOIJQ$#)IFH#$J(PFIHJ#Q(PFHJ@Q(#FHQJ#$(FH#$(FH#$(QFH#$(F*H#$(*FH(EQFHQOEIWFNWOEQJFQOEFNWEKOFNOEW';  // Use a consistent salt for key derivation
    const key = crypto.pbkdf2Sync(hashedPassword, salt, 100000, 32, 'sha512'); // 32 bytes for AES-256
    return key;
}

// Function to hash the password using SHA-512
export function hashPassword(password) {
    return crypto.createHash('sha512').update(password).digest('hex');
}
