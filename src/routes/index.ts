import { Router } from "express";
import authRoutes from "./authRoutes";
import userRoutes from "./userRoutes";

const router = Router();

// Mount auth routes (authentication and algorithms)
router.use("/auth", authRoutes);

// Mount user routes (profile and user data)  
router.use("/user", userRoutes);

export default router;