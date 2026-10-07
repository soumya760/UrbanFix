import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});




// Send OTP email
export const sendOTP = async (email, otp) => {
  const mailOptions = {
    from: `"UrbanFix" <${process.env.EMAIL_FROM}>`,
    to: email,
    subject: "UrbanFix - Your OTP Code",

    text: `Your UrbanFix OTP is ${otp}. This OTP is valid for 10 minutes.`,

    html: `
      <div style="font-family: Arial, sans-serif; padding: 20px;">
        <h2>UrbanFix OTP Verification</h2>

        <p>Hello,</p>

        <p>Your OTP for UrbanFix account verification is:</p>

        <h1 style="letter-spacing: 5px;">${otp}</h1>

        <p>This OTP is valid for <strong>10 minutes</strong>.</p>

        <p>Please do not share this OTP with anyone.</p>

        <br>

        <p>Regards,<br>
        <strong>UrbanFix Team</strong></p>
      </div>
    `,
  };

  const info = await transporter.sendMail(mailOptions);

  console.log("✅ OTP email sent successfully!");
  console.log("📩 Message ID:", info.messageId);

  return info;
};


export const sendPasswordResetEmail = async (email, resetLink) => {
  const mailOptions = {
    from: `"UrbanFix" <${process.env.EMAIL_FROM}>`,
    to: email,
    subject: "UrbanFix - Reset Your Password",

    text: `Reset your UrbanFix password using this link: ${resetLink}. This link is valid for 15 minutes.`,

    html: `
      <div style="font-family: Arial, sans-serif; padding: 20px;">
        <h2>UrbanFix Password Reset</h2>

        <p>Hello,</p>

        <p>We received a request to reset your UrbanFix password.</p>

        <p>
          <a href="${resetLink}"
             style="display:inline-block;padding:12px 20px;background:#007bff;color:white;text-decoration:none;border-radius:5px;">
            Reset Password
          </a>
        </p>

        <p>This link is valid for <strong>15 minutes</strong>.</p>

        <p>If you did not request this, you can safely ignore this email.</p>

        <br>

        <p>Regards,<br>
        <strong>UrbanFix Team</strong></p>
      </div>
    `,
  };

  const info = await transporter.sendMail(mailOptions);

  console.log("Password reset email sent successfully!");
  console.log("Message ID:", info.messageId);

  return info;
};

export default transporter;