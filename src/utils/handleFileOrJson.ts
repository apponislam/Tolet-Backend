import { Request, Response, NextFunction } from "express";
import { uploadProfile } from "../app/middlewares/uploadProfile";
import { parseFormDataJson } from "./parseFormData";

/**
 * Middleware to handle optional file uploads (single/multiple) or raw JSON
 * @param options.fileField - name of file field in form-data
 * @param options.multiple - true if multiple files expected
 * @param options.maxCount - max number of files for multiple upload
 * @param options.jsonField - field containing JSON string (default "data")
 */
interface Options {
    fileField?: string;
    multiple?: boolean;
    maxCount?: number;
    jsonField?: string;
}

export const handleFileOrJson = (options: Options = {}) => {
    const { fileField, multiple = false, maxCount = 10, jsonField = "data" } = options;

    return (req: Request, res: Response, next: NextFunction) => {
        const contentType = req.headers["content-type"] || "";

        if (contentType.startsWith("multipart/form-data") && fileField) {
            const uploadFn = multiple ? uploadProfile.array(fileField, maxCount) : uploadProfile.single(fileField);

            uploadFn(req, res, (err) => {
                if (err) {
                    console.error("File upload error:", err);
                    return next(err);
                }

                // Check if JSON field exists and needs parsing - SAFELY
                if (req.body && typeof req.body === "object" && req.body[jsonField] !== undefined) {
                    parseFormDataJson(jsonField)(req, res, next);
                } else {
                    next();
                }
            });
        } else {
            // For raw JSON or other content types, skip file processing
            next();
        }
    };
};
