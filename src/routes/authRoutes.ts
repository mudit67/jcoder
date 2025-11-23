import { Router } from "express";
import { signup } from "../controllers/authController";

const router = Router();

/**
 * POST /signup
 * Body: { username, password, secretMessage }
 */
router.post("/signup", signup);

export default router;