import sqlite3 from 'sqlite3';
sqlite3.verbose()
let db = new sqlite3.Database('database/real_database.db');
db.get("PRAGMA cipher_version;", (err, row) => {
    if (err) {
        return console.error('Error retrieving cipher version:', err.message);
    }
    console.log(row);
});

db.run("PRAGMA key = 'death to the pope';", (err) => {
    if (err) {
        return console.error('Error running PRAGMA key:', err.message);
    }
    // Force SQLCipher settings to initialize
    db.run("PRAGMA cipher_page_size = 4096;", (err) => {
        if (err) {
            return console.error('Error running cipher_page_size:', err.message);
        }
    });

    db.run("PRAGMA cipher_compatibility = 3;", (err) => {
        if (err) {
            return console.error('Error running cipher compatibility:', err.message);
        }
    });

    db.get("PRAGMA integrity_check;", (err, result) => {
        if (err) {
            return console.error('Error running integrity check:', err.message);
        }
        console.log(result);
    });

    db.prepare("SELECT * FROM users;", (err, row) => {
        if (err) {
            return console.error('Error retrieving data:', err.message);
        }
        console.log(row);
    });
});

db.close();
