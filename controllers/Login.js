


import jwt from 'jsonwebtoken';
import Joi from 'joi';
import bcrypt from 'bcryptjs';
import User from '../models/User.js';
import { createError } from '../utils/createError.js';
import dotenv from 'dotenv';
import { cookieOptions, userDataProperties } from '../utils/authUtilities.js';
dotenv.config();


const salt = bcrypt.genSaltSync(10);


export const SignIn = async (req, res, next) => {
    // Validate request payload
    const validationSchema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(3).required()
    });

    const { error, value } = validationSchema.validate(req.body);
    if (error) {
        return next(createError(400, error.details[0].message));
    }

    try {
        const { email, password } = value; // Use validated value
        // Attempt to find the user by email
        const user = await User.findOne({ email: email.toLowerCase() });

        if (!user) {
            return next(createError(400, "User not found!"));
        }

        // Asynchronously compare the password with the hashed password
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) {
            return next(createError(400, "Wrong credentials!"));
        }

        // Generate tokens
        const refreshTokenExpiration = 30 * 24 * 60 * 60 * 1000; // 30 days in milliseconds
        const accessToken = jwt.sign({ userId: user._id }, process.env.jwtKey, { expiresIn: '30d' });
        const refreshToken = jwt.sign({ userId: user._id }, process.env.jwtKey, { expiresIn: '30d' });

        // Set tokens in cookies
        res.cookie("accessToken", accessToken, cookieOptions());
        res.cookie("refreshToken", refreshToken, { httpOnly: true, maxAge: refreshTokenExpiration });

        // Respond with user data and tokens
        return res.status(200).json({
            success: true,
            message: "Login Successful",
            userData: user,
            accessToken,
            refreshToken
        });
    } catch (err) {
        // Handle unexpected errors
        console.log(err);
        next(err);
    }
};

export const signUp = async (req, res, next) => {
    // Validate request payload
    const validationSchema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(3).required(),
        username: Joi.string().required()
    });

    const { error, value } = validationSchema.validate(req.body);
    if (error) {
        return next(createError(400, error.details[0].message));
    }

    try {
        const { email, password, username } = value; // Use validated values
        // Check if user already exists
        let user = await User.findOne({ email: email.toLowerCase() });

        if (user && user.password) {
            // User exists and has a password already
            return next(createError(400, "Email already exists"));
        } else if (user && !user.password) {
            // User exists without a password (e.g., signed up via social login)
            user.password = await bcrypt.hash(password, parseInt(process.env.SALT_ROUNDS));
            await user.save();
        } else {
            // New user creation
            const hash = await bcrypt.hash(password, parseInt(process.env.SALT_ROUNDS));
            user = new User({
                email: email.toLowerCase(),
                password: hash,
                username
            });
            await user.save();
        }

        // Generate tokens for the user
        const token = jwt.sign({ userId: user._id }, process.env.jwtKey, { expiresIn: '30d' });
        const refreshTokenExpiration = 30 * 24 * 60 * 60 * 1000; // 30 days in milliseconds
        const refreshToken = jwt.sign({ userId: user._id }, process.env.jwtKey, { expiresIn: '30d' });

        // Set tokens in cookies
        res.cookie("accessToken", token, cookieOptions());
        res.cookie("refreshToken", refreshToken, { httpOnly: true, maxAge: refreshTokenExpiration });

        // Respond with user data and tokens
        return res.status(200).json({
            success: true,
            userData: user,
            accessToken: token,
            refreshToken
        });
    } catch (err) {
        // Handle unexpected errors
        console.log(err);
        next(err);
    }
};


export const getUser = async (req, res, next) => {
    try {
        const users = await User.find();
        return res.status(200).json({ success: true, users });
    } catch (err) {
        next(err);
        console.log(err);
    }
}

const tokenExpiration = 30 * 24 * 60 * 60 * 1000;

export const refreshAccessToken = async (req, res, next) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return next(createError(400, "Refresh token not provided"));
    }

    try {
        // Verifying the provided refresh token
        const decodedRefreshToken = jwt.verify(refreshToken, process.env.jwtKey);
        const user = await User.findById(decodedRefreshToken.userId);

        if (!user) {
            return next(createError(400, "User not found!"));
        }

        // Generating a new access token
        const accessToken = jwt.sign({ userId: user._id }, process.env.jwtKey, { expiresIn: '30d' });

        // Update the accessToken in cookies
        res.cookie("accessToken", accessToken, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });

        // Respond with the new access token
        return res.status(200).json({
            success: true,
            message: "Token refreshed successfully",
            accessToken
        });
    } catch (err) {
        console.error(err);
        return next(createError(400, "Invalid refresh token"));
    }
};


export const logout = async (req, res, next) => {
    res
        .clearCookie("accessToken", {
            sameSite: "none",
            secure: true,
        })
        .status(200)
        .send("User has been logged out.");
};

