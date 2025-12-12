import path from "path";
import fs from "fs";
import multer from "multer";

const rootDir = path.join(process.cwd(), "uploads", "profile");
if (!fs.existsSync(rootDir)) {
    fs.mkdirSync(rootDir, { recursive: true });
}

// const storage = multer.diskStorage({
//     destination: (_req, _file, cb) => {
//         cb(null, rootDir);
//     },
//     filename: (_req, file, cb) => {
//         const uniqueName = Date.now() + "-" + Math.round(Math.random() * 1e9);
//         const ext = path.extname(file.originalname);
//         cb(null, uniqueName + ext);
//     },
// });

const storage = multer.diskStorage({
    destination: (_req, _file, cb) => {
        cb(null, rootDir);
    },
    filename: (_req, file, cb) => {
        const isoString = new Date().toISOString(); // 2025-09-10T17:51:38.377Z
        const safeTime = isoString.replace(/:/g, "-").replace(/\./g, "-").replace("Z", "");
        const random = Math.round(Math.random() * 1e9);
        const ext = path.extname(file.originalname);
        cb(null, `${safeTime}-${random}${ext}`);
    },
});

export const uploadProfile = multer({ storage });
