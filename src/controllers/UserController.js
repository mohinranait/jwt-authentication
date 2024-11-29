const createError = require("http-errors");
const User = require("../models/UserModal");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { productionMode, jwtSecret } = require("../accessEnv");

const createNewUser = async (req, res,next) => {
    try {
        const {name, email, password } = req.body || {};
        const body = req.body;
        const {firstName, lastName} = name || {};

        // Input validation
        if(!name) throw createError(409, "Name is required")
        if(!firstName) throw createError(400, "First Name is required")
        if(!lastName) throw createError(400, "Last Name is required")
        if(!email) throw createError(400, "Eamil is required")
        if(!password) throw createError(400, "Password is required")

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

        return res.status(201).send({
            message: 'User created',
            success: true,
            user,
            hashPassword
        })

    } catch (error) {
        next(error)
    }
}

// Login User
const loginUser = async (req, res,next) => {
    try {
        const { email, password } = req.body || {};


        if(!email) throw createError(400, "Eamil is required")
        if(!password) throw createError(400, "Password is required")

        // Duplicate user OR email check
        let isExists = await User.findOne({email});
        if(!isExists)  throw createError(404, "not found");
       

        // Match password
        const matchPass = await bcrypt.compare(password, isExists?.password);
        if(!matchPass) throw createError(401, "forbidden")

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

      

        return res.status(200).send({
            message: 'Login successfully',
            success: true,
            user:isExists,
        })

    } catch (error) {
        next(error)
    }
}


module.exports = {
    createNewUser,
    loginUser 
}