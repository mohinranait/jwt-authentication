require('dotenv').config();
const SERVER_PORT = process.env.PORT || 5000;
const DATABASE = process.env.DATABASE_URL;
const productionMode = process.env.NODE_ENV
const jwtSecret = process.env.JWT_SECRET;
module.exports = {
    SERVER_PORT,
    DATABASE,
    productionMode,
    jwtSecret
}