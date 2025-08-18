import jwt from 'jsonwebtoken';
import mariadb from 'mariadb';
import bcrypt from 'bcryptjs';
import AWS from 'aws-sdk';

const docClient = new AWS.DynamoDB.DocumentClient();
const dynamoDbTable = process.env.DYNAMODB;

const tokenOptions = {
    algorithm: 'HS256',
    expiresIn: '10m',
    issuer: process.env.ISSUER
}

const refreshTokenOptions = {
    algorithm: 'HS256',
    expiresIn: '30d',
    issuer: process.env.ISSUER
}

const createConnection = async () => {
    return await mariadb.createConnection({
        host: process.env.HOSTNAME,
        user: process.env.USERNAME,
        password: process.env.PASSWORD,
        database: process.env.DATABASE
    });
}

const createResponse = (resultCode, body = {}) => {
    return {
        statusCode: resultCode,
        headers: {
            "Access-Control-Allow-Origin": "*"
        },
        body: JSON.stringify(body)
    }
}

export const login = async (event) => {
    const body = JSON.parse(event.body)
    const userId = body.userId;
    const password = body.password;

    if (userId && password) {
        let connection = await createConnection();

        console.log(userId)

        try {

            const [user] = await connection.query(
                'select * from user where user_id = ?;',
                [userId.trim()]
            )

            if (user && bcrypt.compareSync(password, user.password)) {

                console.log('passwordCheck : true')

                delete user.password;

                const token = jwt.sign(user, process.env.SECRET, tokenOptions);
                const refreshToken = jwt.sign(user, process.env.SECRET, refreshTokenOptions);

                const date = new Date();
                date.setDate(date.getDate() + 30);

                const dynamoDbParams = {
                    TableName: dynamoDbTable,
                    Item: {
                        "user_idx": user.idx,
                        "refresh_token": refreshToken,
                        "expireTimestamp": Math.floor(date.getTime() / 1000)
                    }
                };
                await docClient.put(dynamoDbParams).promise();

                connection.destroy();
                return createResponse(200, {token, refreshToken});

            } else {
                connection.destroy();
                return createResponse(401, {message: 'NOT_FOUND'});
            }

        }
        catch (err) {
            connection.destroy();
            return createResponse(500, {message: err.message});
        }
    }else {
        return createResponse(500, {message: 'PARAMETER_ERROR'});
    }

}


export const refresh = async (event) => {
    const body = JSON.parse(event.body)
    const refreshToken = body.refreshToken;
    let connection = await createConnection();

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET, {issuer: process.env.JWT_ISSUER});
        if (decoded.uid) {
            try {
                const dynamoDbSelectParams = {
                    TableName: dynamoDbTable,
                    Key: {
                        "user_idx": decoded.uid,
                        "refresh_token": refreshToken
                    }
                };

                const dynamoDbData = await docClient.get(dynamoDbSelectParams).promise();
                if (!dynamoDbData.Item) {
                    connection.destroy();
                    return createResponse(404, {message: 'NOT_FOUND'});
                }

                const [user] = await connection.query(
                    'select * from user where user_id = ?;',
                    [decoded.trim()]
                )

                if (user) {

                    delete user.password;

                    const token = jwt.sign(user, process.env.SECRET, tokenOptions);
                    const newRefreshToken = jwt.sign(user, process.env.SECRET, refreshTokenOptions);

                    const date = new Date();
                    date.setDate(date.getDate() + 30);
                    const dynamoDbParams = {
                        TableName: dynamoDbTable,
                        Item: {
                            "user_dx": user.idx,
                            "refresh_token": newRefreshToken,
                            "expireTimestamp": Math.floor(date.getTime() / 1000)
                        }
                    };
                    await docClient.put(dynamoDbParams).promise();

                    const dynamoDbDeleteParams = {
                        TableName: dynamoDbTable,
                        Key: {
                            "userIdx": decoded.uid,
                            "refreshToken": refreshToken
                        }
                    };
                    await docClient.delete(dynamoDbDeleteParams).promise();

                    connection.destroy();
                    return createResponse(200, {token, refreshToken: newRefreshToken, decoded});
                } else {
                    connection.destroy();
                    return createResponse(404, {message: 'NOT_FOUND'});
                }
            } catch (err) {
                connection.destroy();
                return createResponse(500);
            }
        } else {
            connection.destroy();
            return createResponse(500, {message: 'PARAMETER_ERROR'});
        }
    } catch (err) {
        connection.destroy();
        if (err.name === 'TokenExpiredError') {
            return createResponse(403);
        }
        return createResponse(500);
    }

}

export const logout = async (event) => {
    const body = JSON.parse(event.body)
    const refreshToken = body.refreshToken;
    let connection = await createConnection();
    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET, {issuer: process.env.JWT_ISSUER});
        if (decoded.uid) {
            try {
                const dynamoDbDeleteParams = {
                    TableName: dynamoDbTable,
                    Key: {
                        "user_dx": decoded.uid,
                        "refresh_token": refreshToken
                    }
                };
                await docClient.delete(dynamoDbDeleteParams).promise();

                connection.destroy();
                return createResponse(200);

            } catch (err) {
                connection.destroy();
                return createResponse(500, err);
            }
        } else {
            connection.destroy();
            return createResponse(500, {message: 'PARAMETER_ERROR'});
        }
    } catch (err) {
        connection.destroy();
        return createResponse(500, err);
    }
}