import { z } from "zod";

// accountType enum
const accountTypes = ["email", "google", "facebook", "github", "apple"] as const;

export const registerSchema = z.object({
    name: z.string().nonempty("Name is required").min(2, "Name must be at least 2 characters").max(50, "Name must be at most 50 characters"),
    email: z
        .string()
        .nonempty("Email is required")
        .refine((val) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val), {
            message: "Invalid email address",
        }),
    password: z.string().min(6, "Password must be at least 6 characters").max(100, "Password must be at most 100 characters").optional(), // make optional for OAuth users
    phone: z
        .string()
        .optional()
        .refine((val) => !val || /^\+?\d{7,15}$/.test(val), { message: "Invalid phone number" }),
    role: z.enum(["user", "admin", "moderator", "super_admin"]).optional().default("user"),
    accountType: z.enum(accountTypes).default("email"),
});

export type RegisterInput = z.infer<typeof registerSchema>;

export const loginSchema = z.object({
    email: z
        .string()
        .nonempty("Email is required")
        .refine((val) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val), {
            message: "Invalid email address",
        }),
    password: z.string().nonempty("Password is required").min(6, "Password must be at least 6 characters").max(100, "Password must be at most 100 characters"),
});

export type LoginInput = z.infer<typeof loginSchema>;
