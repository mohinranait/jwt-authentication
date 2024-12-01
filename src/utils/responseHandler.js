
// Send error response
const errorResponse = (res, { statusCode = 500, message = 'Internal server error' }) => {
    return res.status(statusCode).send({
        message,
        success: false,
    })
}


// Send success response 
const successResponse = (res, { statusCode = 200, message = 'Success', payload = {} }) => {
    return res.status(statusCode).send({
        success: true,
        message,
        payload,
    })
}

module.exports = {
    errorResponse,
    successResponse,
}