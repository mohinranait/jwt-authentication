const { jwtSecret } = require("../accessEnv");
const jwt = require('jsonwebtoken');
const { errorResponse } = require("../utils/responseHandler");

exports.isAuth = async (req, res,next) => {
   
    const token = req.cookies?.access_token;
    if(!token) {
        return errorResponse(res, {
            statusCode: 401,
            message:"Unauthorize token",
        })
    }

    jwt.verify(token, jwtSecret , function(err, decoded) {
        if(err){
            return res.status(401).send({
                message: err.message,
                success: false,
            })
        }

        req.user = decoded;
        next()
    });

}