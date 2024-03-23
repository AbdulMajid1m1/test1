import express from 'express';
import { SignIn, signUp, logout, refreshAccessToken, getUser } from '../controllers/Login.js';

import { auth } from '../middleware/auth.js';
const router = express.Router();
// router.post("/getUrlData", getUrlData);
router.post('/signUp', signUp);
router.get('/getUsers', getUser);
router.post('/login', SignIn);
router.post('/refreshToken', auth, refreshAccessToken);
router.post('/logout', logout);


router.get("/", (req, res) => {
    res.send("API is running!");
});


export default router;

