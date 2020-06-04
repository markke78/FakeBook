const express = require("express");
//const mongo = require("../inMongo");
const Post = require("../models/Posts");
//const config = require("config");
const { check, validationResult } = require("express-validator");
const Router = express.Router;
const database = require("../database/database");
const jwt = require("jsonwebtoken");
const { basicAuth, jwtAuth, createJWT } = require("./auth");

const setupV1Routes = (apiRouter) => {
  // Controller Functions

  async function findAllPosts(request, response) {
    try {
      const posts = await Post.find().sort({ date: -1 });
      response.json(posts);
    } catch (err) {
      console.error(err.message);
      response.status(500).send("Server Error");
    }
    //   let allPosts = database.findAllPosts();
    //   response.send(allPosts);
  }

  async function addNewPost(request, response) {
    let post = new Post(request.body);
    console.log("saving post", request.body);
    await post.save();
    response.sendStatus(200);
  }

  async function clearAllPosts(request, response) {
    try {
      const posts = await Post.find().remove({});
      response.json(posts);
      response.sendStatus(200);
      console.log(posts);
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server Error");
    }
  }

  async function deletePost(request, response) {
    try {
      const post = await Post.find({ uid: request.body.uid }).remove({});
      response.json(post);
      response.sendStatus(200);
      // await post.remove();
    } catch (err) {
      console.error(err.message);

      res.status(500).send("Server Error");
    }
  }

  function updatePost(request, response) {
    database.updatePost(request.body);
    response.sendStatus(200);
  }

  // const textParser = bodyParser.json()

  // Routing
  const v1Router = Router();
  v1Router.get("/posts", findAllPosts);
  // v1Router.post("/addPost", addNewPost);
  v1Router.post("/addPost", jwtAuth, addNewPost);
  v1Router.post("/clear", clearAllPosts);
  v1Router.post("/delete", jwtAuth, deletePost);
  v1Router.post("/updatePost", updatePost);
  v1Router.post("/login", basicAuth, createJWT);
  // v1Router.post("/createUser", createUserDB);

  apiRouter.use("/v1", v1Router);
};

const apiRouter = Router();
setupV1Routes(apiRouter);

module.exports = apiRouter;
