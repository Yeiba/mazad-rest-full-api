import mongoose from "mongoose";
import Redis from 'ioredis'
import redis from 'redis'
import { MongoMemoryServer } from "mongodb-memory-server";
import dotenv from 'dotenv';
dotenv.config()


async function connect() {
    // const mongod = await MongoMemoryServer.create();
    // const getUri = mongod.getUri();
    // mongoose.Promise = Promise
    // mongoose.set('strictQuery', true)
    // const db = await mongoose.connect(getUri);
    try {
        const mongoURL = 'mongodb://mongo_one:27017,mongo_one:27017,mongo_one:27017/'
        const db = await mongoose.connect(mongoURL)
            .then(() => console.log('successfully connected to MongoDB'))
            .catch(err => {
                console.log('we might not be as connected as I thought')
                console.log(err)
            })

        return db;
    } catch (error) {
        console.log('we might not be as connected to db', error)
    }


}

async function cachRedisClient() {
    try {
        // const client = redis.createClient({ url: "redis://redis_one:6379", });
        const client = new Redis({ port: 6379, host: "redis_one" });
        client.on("error", (err) => console.log("Redis Cach Client Connection Error"));
        // await client.connect();
        console.log("Redis cashe app database connected...");
        return client;
    } catch (error) {
        console.log('Redis cash app connection Error...', error);
    }
}
async function sessionRedisClient() {
    try {
        // const client = redis.createClient({ url: "redis://redis_one:6379", });
        const client = new Redis({ port: 6379, host: "redis_two" });
        client.on("error", (err) => console.log("Redis Session Client Connection Error"));
        // await client.connect();
        console.log("Redis Session app database connected...");
        return client;
    } catch (error) {
        console.log('Redis Session app connection Error...', error);
    }
}


export { connect, cachRedisClient, sessionRedisClient };