import { ZodError } from "zod";
import { TErrorSources, TGenericErrorResponse } from "../app/interfaces/error";

const handleZodError = (err: ZodError): TGenericErrorResponse => {
    const errorSources: TErrorSources = err.issues.map((issue) => {
        const lastPath = issue.path[issue.path.length - 1];
        return {
            path: typeof lastPath === "symbol" ? lastPath.toString() : lastPath,
            message: issue.message,
        };
    });

    const statusCode = 400;

    return {
        statusCode,
        message: "Validation Error",
        errorSources,
    };
};

export default handleZodError;
