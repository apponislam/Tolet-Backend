import { Server } from "http";
import app from "./app";
import config from "./config";
import mongoose from "mongoose";
import http from "http";
import createSuperAdmin from "./scripts/createSuperAdmin";
import { initSocket } from "./socket/socketHelper";

let server: Server;

async function main() {
    try {
        await mongoose.connect(config.mongodb_url as string);
        server = http.createServer(app);

        initSocket(server);

        createSuperAdmin();

        // server.listen(Number(config.port), config.ip || "0.0.0.0", () => {
        //     console.log(`✅ App listening on port ${config.port}`);
        // });
        server.listen(Number(config.port), () => {
            console.log(`✅ App listening on port ${config.port}`);
        });
    } catch (err) {
        console.log("❌ DB Connection Failed:", err);
    }
}

main();

process.on("unhandledRejection", (error) => {
    console.log("❌ Unhandled Rejection detected:", error);

    if (server) {
        server.close(() => {
            process.exit(1);
        });
    } else {
        process.exit(1);
    }
});

process.on("uncaughtException", (error) => {
    console.log("❌ Uncaught Exception detected:", error);

    if (server) {
        server.close(() => {
            process.exit(1);
        });
    } else {
        process.exit(1);
    }
});
