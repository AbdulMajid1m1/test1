import express from 'express';
import { SignIn,signUp,logout,refreshAccessToken} from '../controllers/Login.js';

import { auth } from '../middleware/auth.js';
import passport from "../utils/passportConfig.js";
import { AUTH_REDIRECT } from '../config/config.js';
const router = express.Router();
// router.post("/getUrlData", getUrlData);
router.post('/signUp', signUp);
router.post('/login', SignIn);
router.post('/refresh-dtoken',auth, refreshAccessToken);
// router.post('/forget-password/send-email', forgetPasswordStepOne);
// router.post('/forget-password/verify-code', forgetPasswordStepTwo);
// router.post('/forget-password/reset-password', resetPassword);
router.post('/logout', logout);
router.get("/", (req, res) => {
    res.send("Attract Game API is running!");
});


// Google Routes
// router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
// router.get('/auth/google/callback', passport.authenticate('google', { session: false, failureRedirect: `${AUTH_REDIRECT}/login` }), handleGoogleCallback);

// // Facebook Routes
// router.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));
// router.get('/auth/facebook/callback', passport.authenticate('facebook', { session: false, failureRedirect: `${AUTH_REDIRECT}/login` }), handleFacebookCallback);

export default router;

