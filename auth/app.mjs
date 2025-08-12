import jwt from 'jsonwebtoken';
import bcryptjs from 'bcryptjs';
import aws from 'aws-sdk';
import mariadb from 'mariadb';

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
    const username = body.username;
    const password = body.password;

    return createResponse(200, "test");
}