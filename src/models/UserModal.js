const { Schema, model } = require("mongoose");

const userSchema = new Schema({
    name : {
        firstName: {
            type: String,
            required: true,
            trim:true,
        },
        lastName: {
            type: String,
            required: true,
            trim:true,
        },
    },
    email: {
        type: String,
        required: true,
        trim:true,
        unique: true,
    },
    
    password: {
        type: String,
        required: true,
        trim:true,
    },
    status:{
        type: String,
        default:"Active",
        enum: ['Active', 'Pending', 'Banned'],
    }
});

const User = model("User", userSchema);

module.exports = User;