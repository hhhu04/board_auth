import jwt from 'jsonwebtoken';
import mariadb from 'mariadb';
import bcrypt from 'bcryptjs';

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

