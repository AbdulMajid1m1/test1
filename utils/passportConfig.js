import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as FacebookStrategy } from 'passport-facebook';
import User from '../models/User.js';
import { FACEBOOK_APP_ID, FACEBOOK_APP_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from '../config/config.js';


passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:5000/api/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
    let user = await User.findOne({ email: profile.emails[0].value });

    if (!user) {
        // If user does not exist, create a new user
        user = new User({
            email: profile.emails[0].value,
            username: profile.displayName,
            googleId: profile.id
        });
    } else {
        // If the user exists, update their Google ID
        user.googleId = profile.id;
    }

    await user.save();

    return done(null, user);
}));

passport.use(new FacebookStrategy({
    clientID: FACEBOOK_APP_ID,
    clientSecret: FACEBOOK_APP_SECRET,
    callbackURL: 'http://localhost:5000/api/auth/facebook/callback',
    profileFields: ['id', 'emails', 'name']
}, async (accessToken, refreshToken, profile, done) => {
    let user = await User.findOne({ email: profile.emails[0].value });

    if (!user) {
        user = new User({
            email: profile.emails[0].value,
            username: profile.displayName || profile.name.givenName,
            facebookId: profile.id
        });
    } else {
        user.facebookId = profile.id;
    }

    await user.save();

    return done(null, user);
}));


export default passport;
