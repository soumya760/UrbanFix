import express from "express";
import { register , login , refreshAccessToken, verifyOTP,resendOTP} from "../controllers/authController.js";
import { authMiddleware } from "../middleware/authMiddleware.js";
import { roleMiddleware } from "../middleware/roleMiddleware.js";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/refresh", refreshAccessToken);
router.post("/resend-otp", resendOTP);
router.post("/verify-otp", verifyOTP);

router.get("/me", authMiddleware, (req, res) => {
    return res.status(200).json({
        success: true,
        message: "Authenticated user",
        user: req.user
    });
});



// Admin-only test route

router.get(
  "/admin-only",
  authMiddleware,
  roleMiddleware("admin"),
  (req, res) => {
    res.status(200).json({
      message: "Admin access granted"
    });
  }
);



export default router;