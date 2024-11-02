import Database from 'better-sqlite3';
import bcrypt from 'bcrypt';

// Load the database (will create a file if it doesn't exist)
const dbPath = path.resolve(__dirname, 'house.db'); // Path to the database file
const db = new Database(dbPath, { verbose: console.log }); // Optional verbose logging for debugging

function prompt(question) {
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

function getPostById(db, postId) {
    const stmt = db.prepare('SELECT * FROM posts WHERE id = ?');
    return stmt.get(postId); // Returns a single post as an object
}

function getUsernameById(db, userId) {
    const stmt = db.prepare('SELECT username FROM users WHERE id = ?');
    const user = stmt.get(userId);
    return user ? user.username : null;
}

function getAuraById(db, userId) {
    const stmt = db.prepare('SELECT aura FROM users WHERE id = ?');
    const user = stmt.get(userId);
    return user ? user.aura : null;
}

function plusMinusAura(db, userId, amount) {
    const currentAura = getAuraById(userId);
    if (currentAura === null) return false;

    const newAura = currentAura + amount;
    const updateStmt = db.prepare('UPDATE users SET aura = ? WHERE id = ?');
    return updateStmt.run(newAura, userId).changes > 0; // Returns true if the update succeeded
}

function voteContent(db, id, userId, action, type) {
    let content;
    if (type === 'post') {
        content = getPostById(id);
    } else if (type === 'comment') {
        content = getCommentById(id); // Assuming getCommentById is implemented
    }

    if (!content) return false;

    const votedUsers = content.voted_user_ids ? content.voted_user_ids.split(',') : [];
    if (votedUsers.includes(String(userId))) return false; // Already voted

    // Adjust aura
    const newAura = action === 'up' ? content.aura + 1 : content.aura - 1;
    plusMinusAura(userId, action === 'up' ? 1 : -1); // Adjust user aura

    votedUsers.push(String(userId));
    const updatedVotedUsers = votedUsers.join(',');

    const table = type === 'post' ? 'posts' : 'comments';
    const stmt = db.prepare(`UPDATE ${table} SET aura = ?, voted_user_ids = ? WHERE id = ?`);
    return stmt.run(newAura, updatedVotedUsers, id).changes > 0;
}

function createPost(db, title, topicId, userId, content, tags) {
    const stmt = db.prepare(`
        INSERT INTO posts (title, topic_id, user_id, content, tags, aura, voted_user_ids)
        VALUES (?, ?, ?, ?, ?, 0, '')
    `);
    return stmt.run(title, topicId, userId, content, tags).lastInsertRowid;
}

function createComment(db, postId, userId, content) {
    const stmt = db.prepare(`
        INSERT INTO comments (post_id, user_id, content, aura, voted_user_ids, created_at)
        VALUES (?, ?, ?, 0, '', datetime('now'))
    `);
    return stmt.run(postId, userId, content).lastInsertRowid;
}



