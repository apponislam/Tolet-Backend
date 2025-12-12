import mongoose from "mongoose";
import bcrypt from "bcrypt";
import { UserModel } from "../app/modules/auth/auth.model";
import config from "../config";

async function createSuperAdmin() {
    try {
        // Check if super admin already exists
        const existingAdmin = await UserModel.findOne({ role: "super_admin" });
        if (existingAdmin) {
            console.log("✅ Super admin already exists:", existingAdmin.email);
            return;
        }

        // Hash password
        const passwordHash = await bcrypt.hash(config.superAdminPassword!, Number(config.bcrypt_salt_rounds));

        // Prepare user data
        const tempProfileId = new mongoose.Types.ObjectId();
        const tempLocationId = new mongoose.Types.ObjectId();

        const userData: any = {
            serialId: "BDU-000000-000000",
            name: "Super Admin",
            email: config.superAdminEmail,
            password: passwordHash,
            role: "super_admin",
            isActive: true,
            accountType: "email",
            isEmailVerified: true,
            profile: tempProfileId,
            realtimeLocation: tempLocationId,
        };

        const superAdmin = await UserModel.create(userData);
        const populatedSuperAdmin = await UserModel.findById(superAdmin._id).exec();
        console.log("✅ Super admin created:", populatedSuperAdmin?.email, "with ID:", populatedSuperAdmin?.serialId);
    } catch (error) {
        console.error("❌ Error creating super admin:", error);
    }
}

export default createSuperAdmin;
