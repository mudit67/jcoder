import { Request, Response, NextFunction } from "express";
import { JwtService } from "../services/jwtService";
import { JwtPayload } from "../jwt/utils";

declare global {
  namespace Express {
    interface Request {
      user?: {
        userId: number;
        username: string;
      };
    }
  }
}

/**
 * JWT Authentication middleware
 */
export const authenticateToken = (req: Request, res: Response, next: NextFunction): void => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    res.status(401).json({ error: "Access token is required" });
    return;
  }

  try {
    const availableAlgorithms = JwtService.getAvailableAlgorithms();

    const payload = JwtService.verify(token, {
      algorithms: availableAlgorithms,
      issuer: "jcoder-api",
    }) as JwtPayload & { userId: number; username: string; type?: string };

    if (payload.type && payload.type !== 'access') {
      res.status(401).json({ error: "Invalid token type" });
      return;
    }

    req.user = {
      userId: payload.userId,
      username: payload.username,
    };

    next();
  } catch (err: any) {
    if (err.name === "TokenExpiredError") {
      res.status(401).json({ error: "Token has expired" });
      return;
    }
    
    if (err.name === "JsonWebTokenError") {
      res.status(401).json({ error: "Invalid token" });
      return;
    }

    console.error("Error in token verification:", err);
    res.status(500).json({ error: "Internal server error" });
  }
};