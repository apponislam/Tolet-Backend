import mongoose, { FilterQuery, SortOrder, Types } from "mongoose";
import httpStatus from "http-status";
import ApiError from "../../../errors/ApiError";
import { UserModel } from "../auth/auth.model";
import { IUser } from "../auth/auth.interface";
import { calculatePagination } from "../../../utils/paginationHelper";
import { userSearchableFields } from "./user.constant";

interface IUserFilters {
    searchTerm?: string;
    name?: string;
    email?: string;
    phone?: string;
    role?: string;
    isActive?: boolean;
    accountType?: string;
    serialId?: string;
}

const getAllUsersFromDB = async (filters: IUserFilters, paginationOptions: any) => {
    const { page, limit, skip, sortBy, sortOrder } = calculatePagination(paginationOptions);
    const { searchTerm, ...filtersData } = filters;

    const andConditions: FilterQuery<IUser>[] = [];

    // Search implementation
    if (searchTerm) {
        andConditions.push({
            $or: userSearchableFields.map((field: string) => ({
                [field]: {
                    $regex: searchTerm,
                    $options: "i",
                },
            })),
        });
    }

    // Filters implementation
    if (Object.keys(filtersData).length) {
        const filterConditions = Object.entries(filtersData).map(([field, value]) => {
            if (field === "isActive") {
                return { [field]: value === "true" || value === true };
            }
            return { [field]: value };
        });

        andConditions.push({ $and: filterConditions });
    }

    // Sort condition
    const sortConditions: { [key: string]: SortOrder } = {};
    if (sortBy && sortOrder) {
        sortConditions[sortBy] = sortOrder as SortOrder;
    }

    const whereCondition = andConditions.length > 0 ? { $and: andConditions } : {};

    const result = await UserModel.find(whereCondition).populate("profile").populate("realtimeLocation").sort(sortConditions).skip(skip).limit(limit);

    const total = await UserModel.countDocuments(whereCondition);

    return {
        meta: {
            page,
            limit,
            total,
        },
        data: result,
    };
};

const getSingleUserFromDB = async (id: string) => {
    const result = await UserModel.findById(id).populate("profile").populate("realtimeLocation");
    return result;
};

const softDeleteUserData = async (targetUserId: Types.ObjectId) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const now = new Date();

        // Soft delete user
        const user = await UserModel.findOneAndUpdate({ _id: targetUserId, isDeleted: false }, { isDeleted: true, deletedAt: now }, { new: true, session });

        if (!user) {
            throw new ApiError(httpStatus.NOT_FOUND, "User not found or already deleted");
        }

        await session.commitTransaction();
        session.endSession();

        return user;
    } catch (error) {
        await session.abortTransaction();
        session.endSession();
        throw error;
    }
};

export const userServices = { getAllUsersFromDB, getSingleUserFromDB, softDeleteUserData };
