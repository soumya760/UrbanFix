import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pool from "./config/db.js";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Test route
app.get("/", (req, res) => {
    res.send("UrbanFix API is running!");
});

// Test database connection
const testDatabase = async () => {
    try {
        const connection = await pool.getConnection();

        console.log("MySQL database connected successfully!");

        connection.release();
    } catch (error) {
        console.error("MySQL connection failed:", error.message);
    }
};

testDatabase();

// Start server
app.listen(PORT, () => {
    console.log(`UrbanFix server running on port ${PORT}`);
});