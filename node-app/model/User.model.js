import mongoose from "mongoose";
import ItemModel from '../model/User.model.js'
// import validator from "validator";
// const mongoose = require('mongoose')

export const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, "Please provide unique Username"],
        unique: [true, "Username Exist"]
    },
    password: {
        type: String,
        required: [true, "Please provide a password"],
        unique: false,
        minlength: 8,
    },
    email: {
        type: String,
        required: [true, "Please provide a unique email"],
        unique: true,
        lowercase: true,
        // postedBy: {type: mongoose.Schema.Types.ObjectId, ref: 'ItemModel'},
        // comments: [{ body: "string", by: mongoose.Schema.Types.ObjectId }],
        // dateCreated: Date,
        // validate: [validator.isEmail, "Please provide a valid email"]
    },
    firstName: { type: String },
    lastName: { type: String },
    mobile: { type: Number },
    address: { type: String },
    profile: { type: String }
});

export default mongoose.model.Users || mongoose.model('User', UserSchema);