const express = require("express");
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const router = express.Router();
const jwt = require("jsonwebtoken");
const config = require("config");
// const routerUser = express.Router();
const { check, validationResult } = require("express-validator");
const User = require("../models/User");

router.post(
  "/",
  [
    check("username", "Name is required").not().isEmpty(),
    check("email", "Please enter a valid email").isEmail(),
    check(
      "password",
      "Please enter a password with 6 or more characters"
    ).isLength({ min: 6 }),
  ],
  async (req, res) => {
    console.log("from user validation");
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    // See if user exists
    const { username, password, email } = req.body;

    try {
      let user = await User.findOne({ email });
      if (user) {
        console.log("from users check");
        return res
          .status(400)
          .json({ errors: [{ msg: "User already exists" }] });
      }
      //Get users gravatar
      //   const avatar = gravatar.url(email, {
      //     s: "200",
      //     r: "pg",
      //     d: "mm",
      //   });

      user = new User({
        username,
        email,
        // avatar,
        password,
      });

      //Encrypt password
      const salt = await bcrypt.genSalt(10);

      user.password = await bcrypt.hash(password, salt);

      await user.save();

      //Return jsonwebtoken
      const payload = {
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        config.get("jwtSecret"),
        { expiresIn: 360000 },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      res.status(500).send("Server error");
    }
  }
);

module.exports = router;
