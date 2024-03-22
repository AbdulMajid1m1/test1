import jwt from 'jsonwebtoken';
import { isProduction, jwtKey } from '../config/config.js';

export const userDataProperties = user => ({
    _id: user._id,
    email: user.email,
    username: user.username,
});

export const adminDataProperties = admin => ({
    _id: admin._id,
    email: admin.email,
    username: admin.username,
    role: admin.role
});

export const cookieOptions = () => ({
    httpOnly: true,
    secure: isProduction,
    // sameSite: isProduction ? "none" : "lax"
    sameSite: 'None',
});

export const generateJWT = (user) => {
    const userData = {
        _id: user._id,
        email: user.email,
        username: user.username,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
    };
    return jwt.sign(userData, jwtKey, { expiresIn: '30d' });
};
