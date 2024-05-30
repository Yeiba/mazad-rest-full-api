import jwt from 'jsonwebtoken';
import UserModel from '../model/User.model.js'
import ENV from '../config.js'
import dotenv from 'dotenv';
dotenv.config()

// auth middleware
export default async function Auth(req, res, next) {
    try {
        // access authorize header to validate request
        let token;
        token = req.cookies.access_token
        // token = req.cookies.token

        //  retrive the user details of the logged in user
        if (token) {
            try {
                const decodedToken = await jwt.verify(token, process.env.JWT_SECRET)
                req.user = decodedToken
                // res.status(200).send({ msg: "Authorized user" })
                next()

            } catch (error) {
                res.status(401).send({ error: "No Authorized, Invalid Token" })
            }
        } else {
            res.status(401).send({ error: "No Authorized, No Token" })
        }



    } catch (error) {
        res.status(401).send({ error: "Authentication failed" })
    }
}