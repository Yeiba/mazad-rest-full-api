import { createRequire } from "module";
const require = createRequire(import.meta.url);
import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import morgan from 'morgan';
import { connect } from './database/conn.js';

import router from './router/route.js';
import cookieParser from "cookie-parser";
import { notFoundHandler, errorHandler } from "./middleware/error.js";
import path from "path";
import dotenv from 'dotenv';
dotenv.config()



const corsOptions = {
    credentials: true,
    origin: 'http://localhost:3000',
}
const app = express();
// middleware
app.use(cookieParser())
app.enable("trust proxy");

app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(morgan('tiny'));
app.disable('x-powered-by');

app.use(cors(corsOptions))


const port = process.env.PORT || 8080;
// Api Routes
app.use('/api', router)

if (process.env.NODE_ENV !== 'production') {
    const __dirname = path.resolve()
    app.use(express.static(path.join(__dirname, 'FrontEnd/Mazad/build')))
    app.get('*', (req, res) => {
        res.sendFile(path.resolve(__dirname, 'FrontEnd/Mazad/build/index.html'))
    })
} else {
    app.get('/', (req, res) => {
        res.status(201).json("Home get request")
    });
}

app.use(notFoundHandler);
app.use(errorHandler);



// start server only when we have valide connection on mongodb
connect().then(() => {
    try {
        app.listen(port, () => {
            console.log(`listening on http://localhost:${port}`)
        });
    } catch (error) {
        console.log('cannot connect to the server');
    }
}).catch(error => {
    console.log("Invalid database connection.....!")
    console.log({ error })
});











