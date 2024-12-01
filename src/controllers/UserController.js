const createError = require("http-errors");
const User = require("../models/UserModal");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { productionMode, jwtSecret } = require("../accessEnv");
const { loginSchema, registerSchema } = require("../utils/userValidation");
const { successResponse } = require("../utils/responseHandler");

// Create new user
const createNewUser = async (req, res,next) => {
    try {
        const {name, email, password } = req.body || {};
        const body = req.body;
        const {firstName, lastName} = name || {};

        // Input validation
        if(!name) throw createError(409, "Name is required")
        const {error, value} = registerSchema.validate({firstName, lastName, email, password});
        if(error) throw createError(400, error.details[0].message)
       

       // Duplicate user OR email check
       const isExists = await User.findOne({email});
       if(isExists)  throw createError(409, "This email already exists");
       
        // Hash password
        const salt = bcrypt.genSaltSync(10);
        const hashPassword = bcrypt.hashSync(password, salt);

        let user =  await User.create({...body, password: hashPassword })
        user = user.toObject()
        delete user.password;
    
        if(!user) throw createError(404, "User don't created")

        return successResponse(res, {
            message: "User created",
            payload: user,
            statusCode:201
        })

    
    } catch (error) {
        next(error)
    }
}

// Login User
const loginUser = async (req, res,next) => {
    try {
        const { email, password } = req.body || {};
        const {error, value} = loginSchema.validate({email, password});

        if(error) throw createError(400, error.details[0].message )
        

    
        // Duplicate user OR email check
        let isExists = await User.findOne({email});
        if(!isExists)  throw createError(404, "not found");
       

        // Match password
        const matchPass = await bcrypt.compare(password, isExists?.password);
        if(!matchPass) throw createError(401, "Invalid credentials")

        // convert to plain object and remove password
        isExists = isExists.toObject();
        delete isExists.password


        // create token
        const token = await jwt.sign(
            {
                id: isExists?._id,
                email: isExists?.email,

            }, jwtSecret, { expiresIn: '1d' });

        // send response 
        res.cookie("access_token", token, {
            httpOnly: true,
            secure: productionMode == 'production',
            sameSite: productionMode == 'production' ? 'none' : 'strict'
        })

      
        return successResponse(res, {
            message: "Login successfull",
            payload: isExists,
            statusCode:200
        })

       

    } catch (error) {
        next(error)
    }
}


// Find User
const findUserById = async (req, res ,next) => {
    try {
        let userId = req.params?.id;
        
        const {id, email} = req.user;
        
        const user = await User.findById(userId).select('-password');
        if(!user) throw createError(404, "User not-found")
        
        return successResponse(res, {
            statusCode: 200,
            message: "Success",
            payload: user,
        })
       
    } catch (error) {
        next(error)
    }
}

// Find authenticated USER
const getAuthenticatedUser = async (req, res, next) => {
    try {
        const {id:userId,email} = req.user;
        const user = await User.findById(userId).select('-password');
        if(!user) throw createError(404, "User not-found")

        return successResponse(res, {
            message: "Success",
            payload:user,
            statusCode:200
        })
       
    } catch (error) {
        next(error)
    }
}

// Logout 
const logoutUser = async (req, res, next) => {
    try {
        res.clearCookie('access_token').status(200).json({
            message: "User logout",
            success: true,
        })
    } catch (error) {
        next(error)
    }
}


module.exports = {
    createNewUser,
    loginUser ,
    logoutUser,
    findUserById,
    getAuthenticatedUser
}