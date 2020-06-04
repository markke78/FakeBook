const connectDB = require("./config/db");

function clearAllPosts() {
  return connect()
    .then((db) => db.collection("messages").drop())
    .then((shouldBeTrue) => Promise.resolve())
    .catch((couldBeError) => Promise.resolve());
}

async function addPost(post) {
  connectDB();
}

function updatePost(messageWithNewContent) {
  return connect()
    .then((db) =>
      db
        .collection("messages")
        .findOneAndReplace(
          { _id: messageWithNewContent._id },
          messageWithNewContent,
          { returnOriginal: false }
        )
    )
    .then((findAndModifyResult) => findAndModifyResult.value);
}

function findAllPosts() {
  return connect().then((db) => db.collection("messages").find({}).toArray());
}

function close() {
  return connect().then((db) => {
    connectPromise = undefined;
    return client.close();
  });
}

module.exports = {
  clearAllPosts,
  addPost,
  findAllPosts,
  updatePost,
  close,
};
