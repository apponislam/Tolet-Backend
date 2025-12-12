import type { IUserDocument } from "../app/modules/auth/auth.interface";

declare global {
    namespace Express {
        interface User extends Partial<IUserDocument> {}
    }
}
