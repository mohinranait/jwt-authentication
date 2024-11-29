const express = require('express');
const { SERVER_PORT } = require('./accessEnv');
const { userRoute } = require('./routes');
const rateLimit = require("express-rate-limit")
const createError = require('http-errors');
const cookieParser = require('cookie-parser');
const { connectMongodbDatabase } = require('./config/ConnectMongoDB');

const app = express();

connectMongodbDatabase()

const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minutes
    limit: 50,
    statusCode: 429,
    message: { message: 'Your request is rich. Try again' }
})

app.use(limiter)
app.use(express.json());

// app.use(
//     cors({
//         origin: ['http://localhost:3000', 'https://account-social-media-app.vercel.app'],
//         credentials: true,
//         methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
//     })
// )
app.use(cookieParser())

app.use('/api/', userRoute);

app.get('/',(req, res) => {
    res.send('hello');
})


app.use((req, res, next) => {
    next( createError(404, "route not found") )
})

app.use((err, req,res, next) => {
    return res.status(err.status).send({
        message: err.message,
    })
})


app.listen(SERVER_PORT, () => {
    console.log(`Server is Running at http://localhost:${SERVER_PORT}`);
})




