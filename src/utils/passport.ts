import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as FacebookStrategy } from "passport-facebook";
import config from "../config";
import { authServices } from "../app/modules/auth/auth.services";

// --- GOOGLE ---
passport.use(
    new GoogleStrategy(
        {
            clientID: config.google_client_id!,
            clientSecret: config.google_client_secret!,
            callbackURL: `${config.callback_url}/api/v1/auth/google/callback`,
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const result = await authServices.handleGoogleLogin(profile);

                // Cast to unknown first to satisfy Passport type
                return done(null, result as unknown as Express.User);
            } catch (error) {
                return done(error, false);
            }
        }
    )
);

passport.use(
    new FacebookStrategy(
        {
            clientID: config.facebook_app_id!,
            clientSecret: config.facebook_app_secret!,
            callbackURL: `${config.callback_url}/api/v1/auth/facebook/callback`,
            profileFields: ["id", "displayName", "emails", "photos"],
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const result = await authServices.handleFacebookLogin(profile);

                // Wrap in object with 'user' property if missing
                if ("requiresEmail" in result) {
                    // Facebook requires email branch
                    return done(null, result);
                }

                // Social user branch
                const userWithTokens = {
                    user: result.user, // ensure plain object
                    accessToken: result.accessToken,
                    refreshToken: result.refreshToken,
                };

                return done(null, userWithTokens);
            } catch (error) {
                return done(error, false);
            }
        }
    )
);

export default passport;
