import nodemailer from "nodemailer";
import config from "../config";

interface OtpMailOptions {
    to: string;
    name: string;
    otp: string;
}

export const sendOtpEmail = async ({ to, name, otp }: OtpMailOptions) => {
    const transporter = nodemailer.createTransport({
        host: config.mail.smtp_host,
        port: Number(config.mail.smtp_port),
        auth: {
            user: config.mail.smtp_user,
            pass: config.mail.smtp_pass,
        },
    });

    const html = `
<div style="font-family: Arial, sans-serif; background-color: #f4f6f8; padding: 40px 20px;">
    <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); overflow: hidden;">
        <div style="padding: 40px; text-align: center;">
            <h1 style="color: #333333; font-size: 28px; margin-bottom: 20px;">Password Reset OTP</h1>
            <p style="color: #555555; font-size: 16px;">Hi <strong>${name}</strong>,</p>
            <p style="color: #555555; font-size: 16px; line-height: 1.6;">
                Use the following OTP to reset your password:
            </p>
            <div style="font-size: 32px; font-weight: bold; letter-spacing: 4px; margin: 20px 0;">
                ${otp}
            </div>
            <p style="color: #999999; font-size: 14px;">
                This OTP will expire in 10 minutes.
            </p>
        </div>
    </div>
</div>
`;

    await transporter.sendMail({
        from: `"MyApp" <${config.mail.smtp_user}>`,
        to,
        subject: "Password Reset OTP",
        html,
    });
};
