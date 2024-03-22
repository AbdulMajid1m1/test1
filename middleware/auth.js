import jwt from "jsonwebtoken";
import { createError } from "../utils/createError.js";
import { jwtKey } from "../config/config.js";

export const auth = (req, res, next) => {
  let token = req.cookies.accessToken;

  if (!token && req.headers.authorization) {
    const bearerHeader = req.headers.authorization;
    if (bearerHeader.startsWith('Bearer ')) {
      token = bearerHeader.slice(7, bearerHeader.length); // Extract token part
    }
  }

  if (!token && req.headers['x-access-token']) {
    token = req.headers['x-access-token'];
  }

  if (!token) return next(createError(401, "You are not authenticated!"));
  // console.log(token);

  jwt.verify(token, jwtKey, async (err, payload) => {
    if (err) return next(createError(403, "Token is not valid!"));
    req.user = payload;
    next();
  });
};
