import { Request, Response, NextFunction } from "express";
import httpStatus from "http-status";
import ApiError from "../errors/ApiError";

export const parseFormDataJson = (fieldName: string = "data") => {
    return (req: Request, res: Response, next: NextFunction) => {
        try {
            // Safely check if req.body exists and has the field
            if (!req.body || typeof req.body !== "object" || !(fieldName in req.body)) {
                return next();
            }

            let fieldValue = req.body[fieldName];

            // Handle array case
            if (Array.isArray(fieldValue)) {
                if (fieldValue.length === 0) {
                    delete req.body[fieldName];
                    return next();
                }
                fieldValue = fieldValue[0]; // take first element
            }

            // Only parse if it's a non-empty string
            if (typeof fieldValue === "string" && fieldValue.trim()) {
                try {
                    const jsonData = JSON.parse(fieldValue);

                    // Create a new body object, preserving files and other fields
                    const newBody = { ...req.body };

                    // Merge the parsed JSON data
                    Object.assign(newBody, jsonData);

                    // Remove the original JSON field
                    delete newBody[fieldName];

                    req.body = newBody;
                } catch (parseError) {
                    console.error("JSON parsing error:", parseError);
                    const apiError = new ApiError(httpStatus.BAD_REQUEST, "Invalid JSON data format in form field");
                    return next(apiError);
                }
            } else if (fieldValue === null || fieldValue === undefined || fieldValue === "") {
                // Remove empty/null fields
                delete req.body[fieldName];
            }

            next();
        } catch (error) {
            console.error("Unexpected error in parseFormDataJson:", error);
            const apiError = new ApiError(httpStatus.INTERNAL_SERVER_ERROR, "Unexpected error processing form data");
            next(apiError);
        }
    };
};
