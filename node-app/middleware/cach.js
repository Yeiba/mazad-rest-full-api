import crypto from 'crypto';


import { cachRedisClient } from '../database/conn.js'

const client = await cachRedisClient()



export async function getHashKey(queryType) {
    return crypto
        .createHash('sha1')
        .update(JSON.stringify(queryType))
        .digest('hex');
}
export async function setToCach(key, time, value) {
    await client.setex(key, time, JSON.stringify(value));
}

export async function getUserFromCach(req, res, next) {

    const { username } = req.params;
    try {

        const key = `GET_USER_${username}`

        client.get(key).then(reply => {
            if (reply) {
                console.log('CACH HIT')
                res.send(JSON.parse(reply));
            } else {
                console.log('CACH MISS')
                next();
            }
        }).catch(err => {
            console.log(err);
            res.status(500).send(err)
        });
    } catch (error) {
        return res.status(404).send({ error: "Cannot Find User Data in cach" });
    }
};
export async function getProfileFromCach(req, res, next) {
    const { userId } = req.user
    try {
        const key = `GET_PROFILE_${userId}`;
        client.get(key).then(reply => {

            if (reply) {
                console.log('CACH HIT')
                res.send(JSON.parse(reply));
            } else {
                console.log('CACH MISS')
                next();
            }
        }).catch(err => {
            console.log(err);
            res.status(500).send(err)
        });
    } catch (error) {
        return res.status(400).send({ error: error.message });
    }
};
export async function getUsersFromCash(req, res, next) {

    try {
        // const key = getHashKey(`GET_USERS`);
        const key = `GET_USERS`
        client.get(key).then(reply => {

            if (reply) {
                console.log('CACH HIT')
                res.send(JSON.parse(reply));
            } else {
                console.log('CACH MISS')
                next();
            }
        }).catch(err => {
            console.log(err);
            res.status(500).send(err)
        });
    } catch (error) {
        return res.status(400).send({ error: "there is problem to find Users in cach" });
    }
};


