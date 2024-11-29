const { createNewUser, loginUser } = require("../controllers/UserController");

const userRoute = require("express").Router();

userRoute.post('/user/create', createNewUser)
userRoute.post('/user/login', loginUser)

module.exports = userRoute;