import { MongoClient, ObjectId } from 'mongodb';
const uri = (typeof process !== 'undefined' && process.env.mongoURI) || 'mongodb://localhost:27017';
const client = new MongoClient(uri);
const dbName = 'house';

async function connectDb() {
    await client.connect();
    console.log("Connected to MongoDB");
    return client.db(dbName);
}

async function getPostById(db, postId) {
    return await db.collection('posts').findOne({ _id: new ObjectId(postId) });
}

async function plusMinusAura(db, userId, amount) {
    const result = await db.collection('users').findOneAndUpdate(
        { _id: new ObjectId(userId) },
        { $inc: { aura: amount } },
        { returnDocument: 'after' }
    );
    return result.ok === 1; // Returns true if the update succeeded
}

async function voteContent(db, id, userId, action, type) {
    let content;
    if (type === 'post') {
        content = await getPostById(db, id);
    } else if (type === 'comment') {
        // Implement getCommentById or replace it with a real function
        return false; // Placeholder until getCommentById is implemented
    }

    if (!content) return false;

    const votedUsers = content.voted_user_ids || [];
    if (votedUsers.includes(userId)) return false; // Already voted

    const auraChange = action === 'up' ? 1 : -1;
    await plusMinusAura(db, userId, auraChange);

    votedUsers.push(userId);

    const updateResult = await db.collection(type === 'post' ? 'posts' : 'comments').findOneAndUpdate(
        { _id: new ObjectId(id) },
        { $set: { aura: content.aura + auraChange, voted_user_ids: votedUsers } }
    );

    return updateResult.ok === 1;
}

async function createPost(db, title, topicId, userId, content, tags) {
    const result = await db.collection('posts').insertOne({
        title,
        topic_id: new ObjectId(topicId),
        user_id: new ObjectId(userId),
        content,
        tags,
        aura: 0,
        voted_user_ids: []
    });
    return result.insertedId;
}

// Usage example
(async () => {
    const db = await connectDb();

    const postId = await createPost(db, "Sample Post", "topicId", "userId", "This is a post content", ["tag1", "tag2"]);
    console.log("Post created with ID:", postId);

    const voteSuccess = await voteContent(db, postId, "userId", "up", "post");
    console.log("Vote successful:", voteSuccess);

    await client.close();
})();
