const { createNewUser, loginUser, logoutUser, findUserById, getAuthenticatedUser } = require("../controllers/UserController");
const { isAuth } = require("../middleware/isAuth");

const userRoute = require("express").Router();

userRoute.post('/user/create', createNewUser)
userRoute.post('/user/login', loginUser)
userRoute.post('/user/logout', isAuth, logoutUser)
userRoute.get('/user/:id', isAuth, findUserById)
userRoute.get('/user', isAuth, getAuthenticatedUser)

module.exports = userRoute;