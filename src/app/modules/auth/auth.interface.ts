import { HydratedDocument, Types } from "mongoose";

export const roles = {
    USER: "user" as const,
    ADMIN: "admin" as const,
    MODERATOR: "moderator" as const,
    SUPER_ADMIN: "super_admin" as const,
};

export type Role = (typeof roles)[keyof typeof roles];

export type AccountType = "email" | "google" | "facebook" | "github" | "apple";

/**
 * Main user interface
 */
export interface IUser {
    serialId: string; // Unique professional ID like BDU-034582-454855

    // Basic info
    name: string;
    email: string;
    password: string;
    phone?: string;
    profileImg?: string;

    // Role & status
    role: Role;
    isActive: boolean;
    deactivatedBy?: string;
    deactivationReason?: string;

    // Account type & authentication
    accountType: AccountType;
    lastLogin?: Date;
    isEmailVerified?: boolean;
    verificationToken?: string;
    verificationTokenExpiry?: Date;

    // OTP / password reset
    resetPasswordOtp?: string;
    resetPasswordOtpExpiry?: Date;

    // Optional references
    profile: Types.ObjectId;
    realtimeLocation: Types.ObjectId;

    // Audit
    createdAt?: Date;
    updatedAt?: Date;
}

// Mongoose document type
export type IUserDocument = HydratedDocument<IUser>;

export interface ISocialUser {
    user: IUserDocument;
    accessToken: string;
    refreshToken: string;
}

export type IFacebookLoginResult = ISocialUser | { requiresEmail: true; profile: { name: string; profileImg?: string } };
