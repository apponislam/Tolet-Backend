import mongoose from "mongoose";
import crypto from "crypto";

function generateRandom6Digits(): string {
    return String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
}

export async function generateRandomId(model: mongoose.Model<any>, prefix = "BDU"): Promise<string> {
    let id = "";
    let exists = true;

    while (exists) {
        id = `${prefix}-${generateRandom6Digits()}-${generateRandom6Digits()}`;
        const doc = await model.exists({ serialId: id });
        exists = !!doc;
    }

    return id;
}
