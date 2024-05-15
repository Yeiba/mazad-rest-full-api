import UserModel from '../model/User.model.js'
import jwt from 'jsonwebtoken';
import bcrypt from "bcryptjs";
import ENV from '../config.js'
import dotenv from 'dotenv';
import NodeRSA from 'node-rsa'
dotenv.config()

import { setToCach } from '../middleware/cach.js';
import { cachRedisClient } from '../database/conn.js'
const client = await cachRedisClient()


const key_private = new NodeRSA(process.env.PRIVATE_KEY)
const key_public = new NodeRSA(process.env.PUBLIC_KEY)
// const UserModel = require('../model/User.model')
// const jwt = require('jsonwebtoken')
// const bcrypt = require('bcrypt')
/** POST: http://localhost:8080/api/register 
 * @param : {
  "username" : "example123",
  "password" : "admin123",
  "email": "example@gmail.com",
  "firstName" : "bill",
  "lastName": "william",
  "mobile": 8009860560,
  "address" : "Apt. 556, Kulas Light, Gwenborough",
  "profile": ""
}
*/
//  middelware for virefy user 
export async function verifyUser(req, res, next) {
    try {
        const { email } = req.method == "GET" ? req.query : req.body

        // check if the user exists

        let existEmail = await UserModel.findOne({ email });
        if (!existEmail) return res.status(404).send({ error: 'Wrong Email ' });
        next();

    } catch (error) {
        return res.status(404).send({ error: "Authentication Error" });
    }
}
//  POST /register
export async function register(req, res) {

    try {
        const { firstName, lastName, username, email, password, re_password } = req.body;

        // check the existing user
        const existUsername = await UserModel.exists({ username })

        // check for existing email
        const existEmail = await UserModel.exists({ email })

        Promise.all([existUsername, existEmail])
            .then(() => {
                if (password === re_password) {
                    bcrypt.hash(password, 10)
                        .then(hashedPassword => {
                            // JWT token

                            const user = new UserModel({
                                firstName,
                                lastName,
                                username,
                                password: hashedPassword,
                                email
                            })
                            if (user) {

                                const token = jwt.sign({
                                    userId: user._id
                                }, process.env.JWT_SECRET, { expiresIn: "30d" })

                                res.status(201).cookie('access_token', token, {
                                    httpOnly: true,
                                    secure: process.env.NODE_ENV !== "development",
                                    sameSite: "strict",
                                    maxAge: 30 * 24 * 60 * 60 * 1000
                                })
                            } else {
                                return res.status(400).send({ error: 'Invalid user credentials' });
                            }
                            const { password, ...rest } = Object.assign({}, user.toJSON())
                            // return save result as a response
                            const encrypted_res = key_public.encrypt(rest, 'base64')
                            // const encrypted_res = encrypted(rest)
                            user.save()
                                .then(result => res.status(201).send({ msg: "Register Successful", data: encrypted_res }))
                                .catch(error => res.status(500).send({ error }))

                        }).catch(error => {
                            return res.status(500).send({
                                error: "Enable to hashed password"
                            })
                        })
                } else {
                    return res.status(500).send({
                        error: "password Not Matche"
                    })
                }
            }).catch(error => res.status(500).send({ error }))



    } catch (error) {
        return res.status(500).send({ error });
    }

}
//  POST /login
export async function login(req, res) {
    // const data = req.body

    // const decrypt_data =
    //     data &&
    //     JSON.parse(key_private.decrypt(data, "utf8") || "{}")

    const { email, password } = req.body

    try {
        UserModel.findOne({ email }).then(user => {
            bcrypt.compare(password, user.password)
                .then(passwordCheck => {
                    if (!passwordCheck) return res.status(400).send({ error: "Wrong Password" })
                    // JWT token
                    const token = jwt.sign({
                        userId: user._id
                    }, process.env.JWT_SECRET, { expiresIn: "30d" })

                    res.status(201).cookie('access_token', token, {
                        httpOnly: true,
                        secure: process.env.NODE_ENV !== "development",
                        sameSite: "strict",
                        maxAge: 30 * 24 * 60 * 60 * 1000
                    })
                    const { password, ...rest } = Object.assign({}, user.toJSON())

                    const encrypted_res = key_public.encrypt(rest, 'base64')

                    return res.status(200).send({
                        msg: "Login successful",
                        data: encrypted_res
                    })
                })
                .catch(error => {
                    return res.status(400).send({ error: "password mismatch" })
                })

        }).catch(error => {
            return res.status(404).send({ error: "user Not found" })
        })
    } catch (error) {
        return res.status(500).send({ error })
    }
}
export async function logout(req, res) {
    try {

        // res.cookie('jwt', '', cookieSession({
        //     httpOnly: true,
        //     expires: new Date(0)
        // }))
        res.cookie('access_token', '', {
            httpOnly: true,
            expires: new Date(0),
        })
        return res.status(200).send({ msg: "User Logged out" })
    } catch (error) {
        return res.status(500).send({ error: "Error Logged out" })
    }
    res.status(200).send();
}
//  GET /users/:username
export async function getUser(req, res) {
    const { username } = req.params;
    try {
        if (!username) return res.status(501).send({ error: "Invalid Username" });
        await UserModel.findOne({ username }).then(async (user) => {
            const { password, ...rest } = Object.assign({}, user.toJSON());
            const encrypted_res = key_public.encrypt(rest, 'base64')

            const key = `GET_USER_${username}`

            // await client.setex(key, 3600, JSON.stringify(encrypted_res));
            setToCach(key, 3600, encrypted_res)
            return res.status(200).send(encrypted_res);
        })
    } catch (error) {
        return res.status(404).send({ error: "Cannot Find User Data" });
    }
}
//  GET /user/profile
export async function getProfile(req, res) {
    const { userId } = req.user
    try {
        if (userId) {
            await UserModel.findById({ _id: userId }).then(async (profile) => {
                /** remove password from user */
                // mongoose return unnecessary data with object so convert it into json
                const { password, ...rest } = Object.assign({}, profile.toJSON())
                const encrypted_res = key_public.encrypt(rest, 'base64')

                const key = `GET_PROFILE_${userId}`;
                // await client.setex(key, 3600, JSON.stringify(encrypted_res));
                setToCach(key, 3600, encrypted_res)

                return res.status(200).send(encrypted_res);
            })
        } else {
            return res.status(401).send({ error: "User not Found" })
        }
    } catch (error) {
        return res.status(400).send({ error: error.message });
    }


}
export async function getUsers(req, res) {

    try {
        await UserModel.find({}).then(users => {
            const user = users.map(user => {
                const { password, ...rest } = Object.assign({}, user.toJSON())
                const encrypted_res = key_public.encrypt(rest, 'base64')
                return encrypted_res
            })
            const key = `GET_USERS`
            setToCach(key, 3600, user)
            return res.status(200).send({ data: user });
        })
    } catch (error) {
        return res.status(400).send({ error: "there is problem to find Users" });
    }

}
export async function updateUser(req, res) {
    try {
        const { userId } = req.user
        if (userId) {
            const body = req.body
            // update user data
            UserModel.updateOne({ _id: userId }, body).then(() => {
                UserModel.findById({ _id: userId }).then(user => {
                    const { password, ...rest } = Object.assign({}, user.toJSON())
                    const encrypted_res = key_public.encrypt(rest, 'base64')
                    return res.status(201).send({
                        msg: 'User Data updated successfully',
                        data: encrypted_res
                    })
                })
            })
        } else {
            return res.status(401).send({ error: "User not Found" })
        }
    } catch (error) {
        return res.status(401).send({ error: "cannot update user data" })
    }
}
export async function deleteUser(req, res) {
    try {
        // const id = req.query.id

        const { userId } = req.user
        if (userId) {
            // const body = req.body
            // update user data

            UserModel.deleteOne({ _id: userId }).then(function () {

                return res.status(201).send({
                    msg: 'User Deleted successfully'
                })
            })

        } else {
            return res.status(401).send({ error: "User not Found" })
        }


    } catch (error) {
        return res.status(401).send({ error: "cannot delete user" })
    }
}
export async function generateOTP(req, res) {
    res.json('generateOTP route')
}
export async function sendOTP(req, res) {
    res.json('sendOTP route')
}
export async function verifyOTP(req, res) {
    res.json('verifyOTP route')
}
export async function createResetSession(req, res) {
    res.json('createResetSession route')
}
export async function resetPassword(req, res) {
    res.json('resetPassword route')
}