const Joi = require('joi');

const registerSchema = Joi.object({
    firstName: Joi.string().trim().required().min(1).max(60).messages({
        'any.required':"First name is required",
        'string.empty':"First name can't empty",
    }),
    lastName: Joi.string().trim().required().min(1).max(60).messages({
        'any.required':"Last name is required",
        'string.empty':"Last name can't empty",
    }),
    email: Joi.string().trim().email().required().messages({
        "any.required": "Email is required",
        "string.email": "Invalid email address",
        "string.empty": "Email can't empty",
    }),
    password:  Joi.string().trim().min(6).required().messages({
        "any.required": "Password is required.",
        "string.empty": "Password can't be empty.",
        'string.min':"Password must be at least 6 characters"
    }),
})


const loginSchema = Joi.object({
    email: Joi.string().trim().email().required().messages({
        "any.required": "Email is required",
        "string.email": "Invalid email format",
        "string.empty": "Email can't empty",
    }),
    password:  Joi.string().trim().required().messages({
        "any.required": "Password is required.",
        "string.empty": "Password can't be empty.",
    }),
});

module.exports = {
    loginSchema,
    registerSchema
};
