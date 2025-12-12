import nodemailer from "nodemailer";
import config from "../config";

interface VerificationMailOptions {
    to: string;
    name: string;
    verificationUrl: string;
}

export const sendVerificationEmail = async ({ to, name, verificationUrl }: VerificationMailOptions) => {
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
            <h1 style="color: #333333; font-size: 28px; margin-bottom: 20px;">Verify Your Email</h1>
            <p style="color: #555555; font-size: 16px;">Hi <strong>${name}</strong>,</p>
            <p style="color: #555555; font-size: 16px; line-height: 1.6;">
                Thank you for registering! Click the button below to verify your email address and activate your account.
            </p>
            <a href="${verificationUrl}" 
                style="display: inline-block; padding: 14px 28px; margin: 25px 0; background-color: #4CAF50; color: #ffffff; font-size: 16px; font-weight: bold; text-decoration: none; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); transition: background-color 0.3s;">
                Verify Email
            </a>
            <p style="color: #999999; font-size: 14px; margin-top: 20px;">
                If you did not create an account, just ignore this email.
            </p>
        </div>
    </div>
</div>
`;

    await transporter.sendMail({
        from: `"MyApp" <${process.env.SMTP_USER}>`,
        to,
        subject: "Verify Your Email",
        html,
    });
};
