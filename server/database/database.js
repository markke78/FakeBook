// const seedMessage = {
//   postText: 'Your very first message',
//   image: "",
//   author: 'Anonymous',
//   postDate: new Date().toISOString().substring(0, 10),
// }

let content = []

let users = [{
  id: 1,
  firstName: 'john',
  lastName: 'doe',
  email: 'john@doe.com',
  username: 'username',
  password: 'password' // Plain text password. VERY BAD. NEVER DO THIS.
}]

// Post functions

function addPost(newContent) {
  content.push(newContent)
}

function updatePost(newContent) {
  const messageToUpdate = content.find((c) => c.uid == newContent.uid)
  if (messageToUpdate) {
    messageToUpdate.postText = newContent.postText
  }
}

function findAllPosts() {
  return content.slice()
}

function clearAllPosts() {
  console.log('clearAllPosts from Database')
  return content = []
}

function deletePost(uid) {
  const filteredArr = content.filter((c) => c.uid !== uid)
  return content = filteredArr
}

function checkUserNameAndPassword(username, password) {
  // find the user
  const user = users.find(u => u.username === username);

  // check if the password is good
  let passwordIsCorrect = user && user.password === password;
  if (passwordIsCorrect) {
    const { password, ...userWithoutPassword } = user; // Rest operator - Takes the rest of the user object besides password.
    return userWithoutPassword;
  }
}

function getUserById(userId) {
  return users.find(u => u.id === userId);
}

// Log in functions

// const seedIdentity ={
//   username: "Luke",
//   password: "password"
// }

// let identity = {}

// let validLogIns = [
//   seedIdentity
// ]


module.exports = {
  addPost,
  findAllPosts,
  updatePost,
  clearAllPosts,
  deletePost,
  getUserById,
  checkUserNameAndPassword
}
