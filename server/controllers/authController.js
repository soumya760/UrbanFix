import bcrypt from "bcryptjs";
import pool from "../config/db.js";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { generateOTP } from "../utils/otp.js";
import { sendOTP } from "../services/emailService.js";




export const register = async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;

        // 1. Validate required fields
        if (!name || !email || !phone || !password) {
            return res.status(422).json({
                success: false,
                message: "Name, email, phone and password are required"
            });
        }

        // 2. Validate email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailRegex.test(email)) {
            return res.status(422).json({
                success: false,
                message: "Invalid email format"
            });
        }

        // 3. Validate phone - exactly 10 digits
        const phoneRegex = /^[0-9]{10}$/;

        if (!phoneRegex.test(phone)) {
            return res.status(422).json({
                success: false,
                message: "Phone number must be exactly 10 digits"
            });
        }

        // 4. Validate password
        // Minimum 8 characters
        // At least one uppercase letter
        // At least one number
        if (
            password.length < 8 ||
            !/[A-Z]/.test(password) ||
            !/[0-9]/.test(password)
        ) {
            return res.status(422).json({
                success: false,
                message:
                    "Password must be at least 8 characters and contain one uppercase letter and one number"
            });
        }

        // 5. Check duplicate email OR phone
        const [existingUser] = await pool.execute(
            `SELECT id, email, phone
             FROM users
             WHERE email = ? OR phone = ?`,
            [email, phone]
        );

        if (existingUser.length > 0) {
            return res.status(409).json({
                success: false,
                message: "Email or phone already exists"
            });
        }

        // 6. Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // 7. Insert user
        const [result] = await pool.execute(
            `INSERT INTO users
            (name, email, phone, password)
            VALUES (?, ?, ?, ?)`,
            [name, email, phone, hashedPassword]
        );

        // 8. Generate OTP
        const otp = generateOTP();
        console.log("Generated OTP:", otp);


        const otpHash = await bcrypt.hash(otp, 10);

        await pool.execute(
            `INSERT INTO otps
    (email, otp_hash, expires_at)
    VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))`,
            [email, otpHash]
        );

        await sendOTP(email, otp);

        // 8. Success response
        return res.status(201).json({
            success: true,
            message: "User registered successfully",
            user: {
                id: result.insertId,
                name,
                email,
                phone
            }
        });

    } catch (error) {
        console.error("Register error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};


export const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Validate required fields
        if (!email || !password) {
            return res.status(422).json({
                success: false,
                message: "Email and password are required"
            });
        }

        // 2. Find user by email
        const [users] = await pool.execute(
            `SELECT id, name, email, phone, password, role,
                    is_verified, is_blocked, two_fa_enabled
             FROM users
             WHERE email = ?
             LIMIT 1`,
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({
                success: false,
                message: "Invalid credentials"
            });
        }

        const user = users[0];

        // 3. Check account verification
        if (!user.is_verified) {
            return res.status(403).json({
                success: false,
                message: "Account not verified"
            });
        }

        // 4. Check if account is blocked
        if (user.is_blocked) {
            return res.status(403).json({
                success: false,
                message: "Account suspended"
            });
        }

        // 5. Compare password with hashed password
        const isPasswordValid = await bcrypt.compare(
            password,
            user.password
        );

        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: "Invalid credentials"
            });
        }

        // 6. Check 2FA
        if (user.two_fa_enabled) {
            return res.status(200).json({
                success: true,
                requires2FA: true
            });
        }

        // 7. Generate JWT Access Token
        const accessToken = jwt.sign(
            {
                id: user.id,
                role: user.role
            },
            process.env.JWT_ACCESS_SECRET,
            {
                expiresIn: "15m"
            }
        );

        const refreshToken = crypto.randomBytes(64).toString("hex");

        await pool.execute(
            `INSERT INTO refresh_tokens
    (user_id, token, expires_at)
    VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))`,
            [user.id, refreshToken]
        );

        // 8. Update last login
        await pool.execute(
            `UPDATE users
             SET last_login = NOW()
             WHERE id = ?`,
            [user.id]
        );

        // 9. Send response
        return res.status(200).json({
            success: true,
            message: "Login successful",
            accessToken,
            refreshToken,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                role: user.role
            }
        });

    } catch (error) {
        console.error("Login error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};

export const refreshAccessToken = async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(401).json({
                success: false,
                message: "Refresh token required"
            });
        }

        const [rows] = await pool.execute(
            `SELECT user_id, token, expires_at, is_revoked
             FROM refresh_tokens
             WHERE token = ?
             LIMIT 1`,
            [refreshToken]
        );

        if (rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: "Invalid refresh token"
            });
        }

        const storedToken = rows[0];

        if (storedToken.is_revoked) {
            return res.status(401).json({
                success: false,
                message: "Refresh token revoked"
            });
        }

        if (new Date(storedToken.expires_at) <= new Date()) {
            return res.status(401).json({
                success: false,
                message: "Refresh token expired"
            });
        }

        const [users] = await pool.execute(
            `SELECT id, role
             FROM users
             WHERE id = ?
             LIMIT 1`,
            [storedToken.user_id]
        );

        if (users.length === 0) {
            return res.status(401).json({
                success: false,
                message: "User not found"
            });
        }

        const user = users[0];

        const newAccessToken = jwt.sign(
            {
                id: user.id,
                role: user.role
            },
            process.env.JWT_ACCESS_SECRET,
            {
                expiresIn: "15m"
            }
        );

        return res.status(200).json({
            success: true,
            accessToken: newAccessToken
        });

    } catch (error) {
        console.error("Refresh token error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};



// ==========================================
// VERIFY OTP
// ==========================================

export const verifyOTP = async (req, res) => {
    try {
        const { email, otp } = req.body;

        // 1. Validate input
        if (!email || !otp) {
            return res.status(422).json({
                success: false,
                message: "Email and OTP are required"
            });
        }

        // 2. Validate OTP format
        if (!/^\d{6}$/.test(otp)) {
            return res.status(422).json({
                success: false,
                message: "OTP must be 6 digits"
            });
        }

        // 3. Find latest OTP
        const [otpRows] = await pool.execute(
            `SELECT id, email, otp_hash, expires_at, attempts
             FROM otps
             WHERE email = ?
             ORDER BY created_at DESC
             LIMIT 1`,
            [email]
        );

        // 4. OTP not found
        if (otpRows.length === 0) {
            return res.status(400).json({
                success: false,
                message: "OTP not found"
            });
        }

        const storedOTP = otpRows[0];

        // 5. Maximum 5 attempts
        if (storedOTP.attempts >= 5) {
            return res.status(429).json({
                success: false,
                message: "Maximum OTP attempts exceeded"
            });
        }

        // 6. Check expiry
        if (new Date(storedOTP.expires_at) <= new Date()) {
            return res.status(400).json({
                success: false,
                message: "OTP expired"
            });
        }

        // 7. Compare OTP
        const isOTPValid = await bcrypt.compare(
            otp,
            storedOTP.otp_hash
        );

        // 8. Wrong OTP
        if (!isOTPValid) {
            await pool.execute(
                `UPDATE otps
                 SET attempts = attempts + 1
                 WHERE id = ?`,
                [storedOTP.id]
            );

            return res.status(400).json({
                success: false,
                message: "Invalid OTP"
            });
        }

        console.log("VERIFY OTP CONTROLLER HIT");

        // Find user
        const [users] = await pool.execute(
            `SELECT id, role
     FROM users
     WHERE email = ?
     LIMIT 1`,
            [email]
        );

        if (users.length === 0) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        const user = users[0];

        // 9. Mark user as verified
        await pool.execute(
            `UPDATE users
             SET is_verified = 1
             WHERE email = ?`,
            [email]
        );

        // 10. Delete OTP after successful verification
        await pool.execute(
            `DELETE FROM otps
             WHERE id = ?`,
            [storedOTP.id]
        );

        // 11. Generate access token
        const accessToken = jwt.sign(
            {
                id: user.id,
                role: user.role
            },
            process.env.JWT_ACCESS_SECRET,
            {
                expiresIn: "15m"
            }
        );
           console.log("TOKEN BLOCK EXECUTED");
        // 12. Generate refresh token
        const refreshToken = crypto.randomBytes(64).toString("hex");

        // 13. Store refresh token
        await pool.execute(
            `INSERT INTO refresh_tokens
    (user_id, token, expires_at)
    VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))`,
            [user.id, refreshToken]
        );

        // 14. Success
        return res.status(200).json({
            success: true,
            message: "OTP verified successfully",
            accessToken,
            refreshToken
        });

    } catch (error) {
        console.error("Verify OTP error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};



// ==========================================
// RESEND OTP
// ==========================================

export const resendOTP = async (req, res) => {
    try {
        const { email } = req.body;

        // 1. Validate email
        if (!email) {
            return res.status(422).json({
                success: false,
                message: "Email is required"
            });
        }

        // 2. Check user
        const [users] = await pool.execute(
            `SELECT id, email, is_verified
             FROM users
             WHERE email = ?
             LIMIT 1`,
            [email]
        );

        if (users.length === 0) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        const user = users[0];

        // 3. Check if already verified
        if (user.is_verified) {
            return res.status(400).json({
                success: false,
                message: "Account is already verified"
            });
        }

        // 4. Find latest OTP
        const [otpRows] = await pool.execute(
            `SELECT id, last_sent_at
             FROM otps
             WHERE email = ?
             ORDER BY created_at DESC
             LIMIT 1`,
            [email]
        );

        // 5. Check 60-second cooldown
        if (otpRows.length > 0) {
            const lastSentAt = new Date(otpRows[0].last_sent_at);
            const currentTime = new Date();

            const differenceInSeconds =
                (currentTime - lastSentAt) / 1000;

            if (differenceInSeconds < 60) {
                const remainingSeconds = Math.ceil(
                    60 - differenceInSeconds
                );

                return res.status(429).json({
                    success: false,
                    message: `Please wait ${remainingSeconds} seconds before requesting another OTP`
                });
            }
        }

        // 6. Generate new OTP
        const otp = generateOTP();

        console.log("Resent OTP:", otp);

        // 7. Hash new OTP
        const otpHash = await bcrypt.hash(otp, 10);

        // 8. Store new OTP
        await pool.execute(
            `INSERT INTO otps
            (email, otp_hash, expires_at, attempts, last_sent_at)
            VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE), 0, NOW())`,
            [email, otpHash]
        );

        await sendOTP(email, otp);

        // 9. Success
        return res.status(200).json({
            success: true,
            message: "OTP resent successfully"
        });

    } catch (error) {
        console.error("Resend OTP error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};