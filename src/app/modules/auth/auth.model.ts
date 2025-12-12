import { model, Schema } from "mongoose";
import { IUser } from "./auth.interface";

const userSchema = new Schema<IUser>(
    {
        serialId: { type: String, unique: true, index: true },
        name: {
            type: String,
            required: [true, "Name is required"],
        },
        email: {
            type: String,
            required: [true, "Email is required"],
            unique: true,
        },
        password: {
            type: String,
            required: function (this: IUser): boolean {
                return this.accountType === "email";
            },
            validate: {
                validator: function (value: string): boolean {
                    // Type the 'this' context
                    const user = this as unknown as IUser;
                    if (user.accountType === "email") {
                        return !!value && value.length > 0;
                    }
                    return true;
                },
                message: "Password is required for email accounts",
            },
        },

        phone: { type: String },
        profileImg: { type: String },
        role: {
            type: String,
            enum: {
                values: ["user", "admin", "moderator", "super_admin"],
                message: "Role must be either user, admin, or moderator",
            },
            default: "user",
        },
        isActive: { type: Boolean, default: true },
        lastLogin: { type: Date },
        accountType: {
            type: String,
            enum: {
                values: ["email", "google", "facebook", "github", "apple"],
                message: "Account type must be email, google, facebook, github, or apple",
            },
            default: "email",
        },

        isEmailVerified: {
            type: Boolean,
            default: function (this: IUser) {
                return this.accountType === "email" ? false : undefined;
            },
        },
        verificationToken: {
            type: String,
            default: function (this: IUser) {
                return this.accountType === "email" ? undefined : undefined;
            },
        },
        verificationTokenExpiry: {
            type: Date,
            default: function (this: IUser) {
                return this.accountType === "email" ? undefined : undefined;
            },
        },
        profile: { type: Schema.Types.ObjectId, ref: "Profile" },
        realtimeLocation: { type: Schema.Types.ObjectId, ref: "RealtimeLocation" },
        resetPasswordOtp: { type: String },
        resetPasswordOtpExpiry: { type: Date },
    },
    {
        timestamps: true,
        versionKey: false,
        toJSON: {
            transform: function (doc, ret) {
                if (ret.password) delete (ret as any).password;
                if (ret.__v) delete (ret as any).__v;
                return ret;
            },
        },
    }
);

userSchema.pre("save", function (next) {
    const user = this as IUser;
    if (user.accountType !== "email") {
        user.isEmailVerified = undefined;
        user.verificationToken = undefined;
        user.verificationTokenExpiry = undefined;
    } else if (user.isEmailVerified === undefined) {
        user.isEmailVerified = false;
    }
    next();
});

// Remove password after save for safety
userSchema.post("save", function (doc, next) {
    doc.password = undefined as any;
    next();
});

export const UserModel = model<IUser>("User", userSchema);
