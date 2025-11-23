import { Request, Response } from "express";
import db from "../db";
import { hashPassword } from "../security/password";
import { SignupRequestBody, UserResponse, ApiResponse } from "../types";

/**
 * Handle user signup
 */
export const signup = async (req: Request<{}, ApiResponse<UserResponse>, SignupRequestBody>, res: Response): Promise<Response> => {
  const { username, password, secretMessage } = req.body;

  // Basic validation
  if (!username || !password || !secretMessage) {
    return res.status(400).json({
      error: "username, password and secretMessage are required",
    });
  }

  try {
    // Check if user already exists
    const existingUser = db.prepare("SELECT username FROM users WHERE username = ?").get(username);
    
    if (existingUser) {
      return res.status(409).json({ error: "Username already taken" });
    }

    // Hash the password
    const passwordHash = await hashPassword(password);
    const createdAt = new Date().toISOString();

    const stmt = db.prepare(
      `
      INSERT INTO users (username, password_hash, secret_message, created_at)
      VALUES (@username, @password_hash, @secret_message, @created_at)
      `
    );

    stmt.run({
      username,
      password_hash: passwordHash,
      secret_message: secretMessage,
      created_at: createdAt,
    });

    return res.status(201).json({
      message: "User created successfully",
      data: {
        username,
        secretMessage,
        createdAt,
      },
    });
  } catch (err: any) {
    console.error("Error in signup:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};