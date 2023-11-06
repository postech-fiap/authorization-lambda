const jwt = require('jsonwebtoken')

const jwtSecret = process.env.JWT_SECRET

const successResponse = {
    principalId: 'me',
    policyDocument: {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
}

const extractTokenFromHeader = (headerValue) => {
    if (headerValue && headerValue.split(' ')[0] === 'Bearer') {
        return headerValue.split(' ')[1];
    }
    return headerValue;
}

exports.handler = async function(event, context, callback) {
    const token = extractTokenFromHeader(event.headers.authentication)
    
    try {
        jwt.verify(token, jwtSecret);
        callback(null, successResponse)
    } catch {
        callback("Unauthorized")
    }
}