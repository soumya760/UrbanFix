import bcrypt from "bcryptjs";
import pool from "../config/db.js";
import jwt from "jsonwebtoken";

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