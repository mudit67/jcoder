import { Request, Response } from "express";
import db from "../db";
import { SecretMessageResponse, ApiResponse, User } from "../types";

/**
 * Get user's secret message with creation time (protected route)
 */
export const getSecretMessage = async (req: Request<{}, ApiResponse<SecretMessageResponse>>, res: Response): Promise<Response> => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const user = db.prepare("SELECT username, secret_message, created_at FROM users WHERE id = ?")
      .get(req.user.userId) as { username: string; secret_message: string; created_at: string } | undefined;

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    return res.status(200).json({
      message: "Secret message retrieved successfully",
      data: {
        secretMessage: user.secret_message,
        username: user.username,
        createdAt: user.created_at,
        retrievedAt: new Date().toISOString(),
      },
    });
  } catch (err: any) {
    console.error("Error in getSecretMessage:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};