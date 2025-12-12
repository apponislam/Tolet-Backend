import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import catchAsync from "../../utils/catchAsync";
import { UserModel } from "../modules/auth/auth.model";
import ApiError from "../../errors/ApiError";
import config from "../../config";

const auth = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    let token = req.headers.authorization;

    if (token?.startsWith("Bearer ")) token = token.slice(7);

    if (!token) {
        throw new ApiError(401, "Authentication failed: No token provided");
    }

    let decoded;
    try {
        decoded = jwt.verify(token, config.jwt_access_secret as string) as { email: string };
    } catch (err: any) {
        if (err.name === "TokenExpiredError") {
            throw new ApiError(401, "Authentication failed: Token expired");
        }
        throw new ApiError(401, "Authentication failed: Invalid token");
    }

    const user = await UserModel.findOne({ email: decoded.email });

    if (!user) {
        throw new ApiError(404, "Authentication failed: User not found");
    }

    // console.log(user);
    // console.log(decoded);

    req.user = user;
    next();
});

export default auth;
