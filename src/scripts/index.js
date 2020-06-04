function add(a, b) {
  return a + b;
}

function subtract(a, b) {
  return a - b;
}

function cleanOutElement(id) {
  $("#" + id).html("");
}

function appendHtml(id, htmlToAdd) {
  $("#" + id).append(htmlToAdd);
}

function setInputValue(id, newValue) {
  return $("#" + id).val(newValue);
}

function getInputValue(id) {
  return $("#" + id).val();
}

function hide(id) {
  $("#" + id).hide();
}

function show(id) {
  $("#" + id).show();
}

function disable(id) {
  $("#" + id).prop("disabled", true);
}

function enable(id) {
  $("#" + id).prop("disabled", false);
}

function inputHasSomeText(id) {
  return getInputValue(id) !== "";
}

function todaysDateString() {
  return new Date().toISOString().substring(0, 10);
}

// getting and setting posts on the page
examplePost = {
  postText: "Hi, this is a test post 0",
  image: "",
  author: "Tony Enerson",
  postDate: "2020-05-19",
};

function addPostToPage(post) {
  if (post.postText !== undefined) {
    let postHtml = `
			<div class="post-card card" id="${post.uid}">
				<div class='post-card-header'>
					<img class="profile-thumbnail" src='https://robohash.org/${post.uid}?set=set2&size=180x180'/>
					<div> 
						${post.author}
						</br>
						<div id='date${post.uid}'>${post.postDate}</div>
					</div>
				</div>
				<div  class="dropdown-container">
					<button class="ellipsis-button" onclick="ellipsisButtonPressed('list${post.uid}')">&#8285;</button>
					<div id="list${post.uid}" class="dropdown-content"> 
						<div class="drop-down-item" onclick="editButtonPressed('${post.uid}', '${post.postText}')"> Edit </div>
							<div class="drop-down-item" onclick="deleteButtonPressed(${post.uid})"> Delete </div>
						</div>
					</div>
				<div id="textArea${post.uid}" class="post-card-text">${post.postText}</div>
				
				<div id="${post.uid}container" class="post-card-text">
	 				<textarea type='text' id="editArea${post.uid}">${post.postText} </textarea>
	 				<button id="saveChangesButton${post.uid}" onclick="saveChangesButtonPressed('${post.uid}')">Save</button>
	 			</div>
		
				<div class="post-footer">
				<button class='button-with-image under-construction' id='likeButton' onClick="likeButtonPressed()"> &#128077;
					Like
				</button>
				<button class='button-with-image under-construction' id='commentButton${post.uid}' onClick="commentButtonPressed(${post.uid})">
					&#128172; Comment
				</button>
			</div>
			
			<div class='comment-area'>
				<input class="comment-input" id='commentInput${post.uid}' placeholder="Write your comment..."/>
			</div>
		</div>
		`;
    appendHtml("newsFeed", postHtml);
    hide(`list${post.uid}`);
    hide(`editArea${post.uid}`);
    hide(`saveChangesButton${post.uid}`);
  }
}

function ellipsisButtonPressed(id) {
  if ($("#" + id).attr("style") == "display: none;") {
    show(id);
  } else {
    hide(id);
  }
}

function editButtonPressed(id, text) {
  let date = getInputValue(`date${id}`);
  console.log(date);
  console.log($("#" + id));

  $("#" + `textArea${id}`).toggle();
  $("#" + `editArea${id}`).toggle();
  $("#" + `saveChangesButton${id}`).toggle();
  hide(`list${id}`);
}

function getPostFromForm(
  inputTextId,
  inputDate = String(todaysDateString()),
  id = String(new Date().getTime())
) {
  let authorName = "Anonymous";
  if (inputHasSomeText(inputTextId)) {
    console.log("post has text");
    authorName = "Anonymous";
  } else {
    // authorName = getInputValue(`${inputTextid}`);
    console.log("post does not have text");
  }
  return {
    postText: getInputValue(inputTextId),
    author: authorName,
    postDate: inputDate,
    uid: id,
  };
}

function postButtonPressed() {
  if (inputHasSomeText("statusInputField")) {
    let postToAdd = getPostFromForm("statusInputField");
    postPostsToServerAndUpdatePage(postToAdd);
    clearInputField("statusInputField");
  } else {
    return "Please Add a Message";
  }
}

function clearInputField(id) {
  $("#" + id).val("");
}

function pressEnterKey(id, actionFunction) {
  $("#" + id).keyup(function (e) {
    let code = e.which;
    if (code == 13) {
      e.preventDefault();
      actionFunction();
    }
  });
}

function commentButtonPressed(cardId) {
  let id = String(cardId);
  $("#commentInput" + id).focus();
}

function clearNewsFeedButtonPressed() {
  clearPostsFromServer();
}

function deleteButtonPressed(id) {
  let data = { uid: String(id) };

  deleteFromServer(data);
}

function createUserButtonPressed() {
  let uname = getInputValue(`createUserInput`);
  let pword = getInputValue(`createPassInput`);
  let email = getInputValue(`createEmailInput`);

  createUser({ username: uname, password: pword, email: email });
}

function saveChangesButtonPressed(id) {
  let newText = getInputValue(`textArea${id}`);
  let date = $("#" + `date${id}`).text();

  console.log(newText);
  // console.log(date)

  let newPost = getPostFromForm(`editArea${id}`, date, `${id}`);
  console.log(newPost);
  console.log(date);

  updateOnePost(newPost);
}

function loginButtonPressed() {
  let pword = getInputValue(`loginPassInput`);
  let email = getInputValue(`loginEmailInput`);
  userLogin({ password: pword, email: email });
}

function updatePagePosts(posts) {
  cleanOutElement("newsFeed");
  posts.forEach(function (post) {
    addPostToPage(post);
  });
}

//---- server interaction
let token = "";

function createUser(userObject) {
  console.log("hey");
  $.ajax({
    url: "/users",
    type: "POST",
    data: JSON.stringify(userObject),
    contentType: "application/json; charset=utf-8",
    success: function (data) {
      console.log("User created");
      token = data.token;
    },
    fail: function () {
      console.log("user exists");
    },
  });
}

//WORK IN PROGRESS
function userLogin(userLoginObject) {
  console.log(userLoginObject);
  $.ajax({
    url: "/api/v1/login",
    type: "POST",
    data: JSON.stringify(userLoginObject),
    contentType: "application/json; charset=utf-8",
    success: function (data) {
      console.log("User logged in");
      token = data.token;
      console.log("Authentication pending");
    },
  });
}

function postPostsToServerAndUpdatePage(post) {
  $.ajax({
    url: "/api/v1/addPost",
    type: "POST",
    data: JSON.stringify(post),
    contentType: "application/json; charset=utf-8",
    headers: {
      Authorization: `Bearer ${token}`,
    },
    success: function () {
      console.log("In post callback");
      updatePostsFromServer();
    },
    fail: function (error) {
      // what do we do here?
    },
  });
}

function updatePostsFromServer() {
  console.log("posts updated");
  $.getJSON("/api/v1/posts")
    .done(function (posts) {
      updatePagePosts(posts);
    })
    .fail(function (error) {
      // what do we do here????
    });
}

function clearPostsFromServer() {
  $.ajax({
    url: "/api/v1/clear",
    type: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
    },
    success: function () {
      console.log("server has been cleared");
      updatePostsFromServer();
    },
    fail: function (error) {
      // what do we do here?
    },
  });
}

function deleteFromServer(post) {
  $.ajax({
    url: "/api/v1/delete",
    type: "POST",
    data: JSON.stringify(post),
    contentType: "application/json; charset=utf-8",
    headers: {
      Authorization: `Bearer ${token}`,
    },
    success: function () {
      console.log("message has been deleted");

      updatePostsFromServer();
    },
    fail: function (error) {
      console.log(error);
    },
  });
}

function updateOnePost(post) {
  $.ajax({
    url: "/api/v1/updatePost",
    type: "POST",
    data: JSON.stringify(post),
    contentType: "application/json; charset=utf-8",
    headers: {
      Authorization: `Bearer ${token}`,
    },
    success: function () {
      console.log(`message ${post.uid} has been updated`);

      updatePostsFromServer();
    },
    fail: function (error) {
      console.log(error);
    },
  });
}

$(document).ready(function () {
  updatePostsFromServer();
});
