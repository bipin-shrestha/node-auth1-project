// Require the `restricted` middleware from `auth-middleware.js`. You will need it here!
const router = require ('express').Router();
const users = require("./users-model.js");
const express = require('express');
const { restricted } = require('../auth/auth-middleware.js');

/**
  [GET] /api/users

  This endpoint is RESTRICTED: only authenticated clients
  should have access.

  response:
  status 200
  [
    {
      "user_id": 1,
      "username": "bob"
    },
    // etc
  ]

  response on non-authenticated:
  status 401
  {
    "message": "You shall not pass!"
  }
 */
router.get('/', restricted, async (req, res, next) => {
  
  try{
    const authUser = await users.find()
    if(authUser){
      res.status(200).json(authUser);
    } else {
      res.status(401).json({ message: "You shall not pass!" })
    }
  }
  catch(error){
    next(error);
  }
})

// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;