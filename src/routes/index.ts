import { Router } from "express";
import authRoutes from "./authRoutes";

const router = Router();

// Mount auth routes directly (no /auth prefix since we're already under /api)
router.use("/", authRoutes);

export default router;