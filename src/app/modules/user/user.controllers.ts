import { Types } from "mongoose";
import catchAsync from "../../../utils/catchAsync";
import { userServices } from "./user.services";
import sendResponse from "../../../utils/sendResponse.";
import { Request, Response } from "express";
import httpStatus from "http-status";
import ApiError from "../../../errors/ApiError";
import { IUser } from "../auth/auth.interface";

const getAllUsers = catchAsync(async (req: Request, res: Response) => {
    // Use req.query directly or use the parsed filters from middleware
    const filters = req.query;
    const paginationOptions = {
        page: req.query.page,
        limit: req.query.limit,
        sortBy: req.query.sortBy,
        sortOrder: req.query.sortOrder,
    };

    const result = await userServices.getAllUsersFromDB(filters, paginationOptions);

    sendResponse<IUser[]>(res, {
        statusCode: 200,
        success: true,
        message: "Users retrieved successfully",
        data: result.data,
        meta: result.meta,
    });
});

const getSingleUser = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;
    const result = await userServices.getSingleUserFromDB(id);

    sendResponse(res, {
        statusCode: 200,
        success: true,
        message: "User retrieved successfully",
        data: result,
    });
});

const deleteMyAccount = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user?._id as Types.ObjectId;
    const user = await userServices.softDeleteUserData(userId);

    sendResponse(res, {
        statusCode: httpStatus.OK,
        success: true,
        message: "Your account and all related data soft deleted",
        data: user,
    });
});

const adminDeleteUser = catchAsync(async (req: Request, res: Response) => {
    const targetUserId = req.params.userId as string;

    if (!Types.ObjectId.isValid(targetUserId)) {
        throw new ApiError(httpStatus.BAD_REQUEST, "Invalid user ID");
    }

    const user = await userServices.softDeleteUserData(new Types.ObjectId(targetUserId));

    sendResponse(res, {
        statusCode: httpStatus.OK,
        success: true,
        message: "User account and all related data soft deleted by admin",
        data: user,
    });
});

export const userControllers = { getAllUsers, getSingleUser, deleteMyAccount, adminDeleteUser };
