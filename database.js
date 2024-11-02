import Database from 'better-sqlite3';
import readline from 'readline';

// Create a readline interface for prompting passphrase
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question('Enter the passphrase to encrypt the database: ', (passphrase) => {
    try {
        // Create a new SQLite database
        const db = new Database('encrypted_house.db');

        // Encrypt the database using the passphrase
        db.pragma(`key = '${passphrase}'`);

        console.log('Encrypted database "encrypted_house.db" created successfully.');

        // Close the readline interface
        rl.close();

        // Close the database connection
        db.close();
    } catch (err) {
        console.error('Error creating the encrypted database:', err);
        rl.close();
    }
});
