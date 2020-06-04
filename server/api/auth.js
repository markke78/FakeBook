const express = require("express");
const mongo = require("../inMongo");
const Post = require("../models/Posts");
const config = require("config");
const { check, validationResult } = require("express-validator");
const Router = express.Router;
const database = require("../database/database");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../models/User");

async function saltHash(based64Credentials) {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(based64Credentials, salt);
}

//Basic auth is cheching user email and password on login
async function basicAuth(request, response, next) {
  // check username and password against database
  const { email, password } = request.body;
  const user = await User.findOne({ email });

  // if user does not exits return 400
  if (!user) {
    return response.status(400).json({
      errors: [{ msg: "Authentication failed: Invalid username or password." }],
    });
  } else {
    const isMatch = await bcrypt.compare(password, user.password);

    //if password does not match return 400
    if (!isMatch) {
      console.log("Invalid username or password");
      return res.status(400).json({
        errors: [
          { msg: "Authentication failed: Invalid username or password." },
        ],
      });
    } else {
      console.log("user checked from basic auth");
      next();
    }
  }
}

function jwtAuth(request, response, next) {
  console.log("from jwt function");
  console.log(request.url);
  // check for jwt auth header
  const noAuth = !request.headers.authorization;

  console.log(request.headers.authorization);
  if (noAuth || request.headers.authorization.indexOf("Bearer ") === -1) {
    console.log("No same token");
    return response
      .status(401)
      .json({ message: "Missing Authorization Header" });
  }

  // pull out the jwt
  const token = request.headers.authorization.split(" ")[1];

  // verify the jwt
  const payload = jwt.verify(token, config.get("jwtSecret"));
  console.log(payload.user.id);

  const user = User.findById(payload.user.id);
  if (user) {
    console.log("you are the user");
    request.user = user;
    return next();
  } else {
    return response.status(401).json({
      message: "JWT Authentication failed: Invalid username or password.",
    });
  }
}

function createJWT(request, response) {
  console.log("from create jwt");
  console.log(request.header);
  console.log(request.user);

  // create JWT and send it back
  const payload = {
    user: {
      id: request.user.id,
    },
  };
  const token = jwt.sign(payload, config.get("jwtSecret"), {
    expiresIn: 1440, // expeires in 24 hours
  });

  console.log(token);

  return response.json({
    message: "login success",
    token: token,
  });
}

module.exports = {
  basicAuth,
  jwtAuth,
  createJWT,
};
