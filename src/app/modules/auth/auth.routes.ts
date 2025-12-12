import { Router } from "express";
import { authControllers } from "./auth.controller";
import validateRequest from "../../middlewares/validateRequest";
import { loginSchema, registerSchema } from "./auth.validation";
import { handleFileOrJson } from "../../../utils/handleFileOrJson";
import passport from "../../../utils/passport";
import auth from "../../middlewares/auth";
const router = Router();

router.post("/register", handleFileOrJson({ fileField: "profile" }), validateRequest(registerSchema), authControllers.register);
router.post("/resend-verify-email", authControllers.resendVerifyEmailController);
router.get("/verify-email", authControllers.verifyEmailController);

router.post("/login", validateRequest(loginSchema), authControllers.login);

// Google Sign In
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));
router.get("/google/callback", passport.authenticate("google", { session: false, failureRedirect: "/login" }), authControllers.googleCallback);

// Facebook Sign In
router.get("/facebook", passport.authenticate("facebook", { scope: ["email"] }));
router.get("/facebook/callback", passport.authenticate("facebook", { session: false }), authControllers.facebookCallback);

router.get("/me", auth, authControllers.getMeController);

router.post("/refresh-token", authControllers.refreshAccessToken);

router.post("/logout", authControllers.logout);

router.post("/forgot-password", authControllers.requestPasswordResetOtpController);
router.post("/resend-reset-otp", authControllers.resendPasswordResetOtpController);
router.post("/reset-password", authControllers.resetPasswordWithOtpController);

router.post("/change-password", auth, authControllers.changePasswordController);

export const authRoutes = router;
