import express from 'express';
import { SignIn,signUp,logout,refreshAccessToken} from '../controllers/Login.mjs';

import { auth } from '../middleware/auth.js';
const router = express.Router();
// router.post("/getUrlData", getUrlData);
router.post('/signUp', signUp);
router.post('/get', get);
router.post('/login', SignIn);
router.post('/refresh-dtoken',auth, refreshAccessToken);
router.post('/logout', logout);
router.get("/", (req, res) => {
    res.send("API is running!");
});


export default router;

