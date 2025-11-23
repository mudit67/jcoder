import { Request, Response } from "express";
import db from "../db";
import { hashPassword, verifyPassword } from "../security/password";
import { SignupRequestBody, LoginRequestBody, RefreshTokenRequestBody, UserResponse, LoginResponse, RefreshTokenResponse, ApiResponse, User } from "../types";
import { JwtService, validateExpiresIn, calculateExpirationTimestamp, getExpirationOptions, parseExpiresIn } from "../services/jwtService";
import { 
  generateRefreshToken, 
  storeRefreshToken, 
  validateRefreshToken, 
  revokeRefreshToken, 
  revokeAllUserTokens,
  rotateRefreshToken,
  calculateRefreshTokenExpiration 
} from "../services/refreshTokenService";

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

/**
 * Handle user login
 */
export const login = async (req: Request<{}, ApiResponse<LoginResponse>, LoginRequestBody>, res: Response): Promise<Response> => {
  const { username, password, algorithm = 'HS256', expiresIn = '24h', issueRefreshToken = false } = req.body;

  // Basic validation
  if (!username || !password) {
    return res.status(400).json({
      error: "username and password are required",
    });
  }

  // Validate expiration duration format
  if (!validateExpiresIn(expiresIn)) {
    return res.status(400).json({
      error: "Invalid expiration format. Use formats like: '15m', '1h', '24h', '7d', '30d' or plain numbers (seconds)",
    });
  }

  try {
    // Check if the requested algorithm is available
    const availableAlgorithms = JwtService.getAvailableAlgorithms();
    if (!availableAlgorithms.includes(algorithm)) {
      return res.status(400).json({
        error: `Algorithm '${algorithm}' is not available. Available algorithms: ${availableAlgorithms.join(', ')}`,
      });
    }

    // Find user by username
    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username) as User | undefined;
    
    if (!user) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // Verify password
    const isPasswordValid = await verifyPassword(password, user.password_hash);
    
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // Calculate expiration timestamp
    const issuedAt = new Date();
    const expiresAt = calculateExpirationTimestamp(expiresIn);

    // Generate JWT access token with selected algorithm and expiration
    const accessToken = JwtService.sign(
      { 
        userId: user.id,
        username: user.username,
        type: 'access'
      },
      {
        algorithm,
        expiresIn,
        issuer: "jcoder-api",
      }
    );

    // Generate refresh token only if user opted for it
    let refreshToken: string | undefined;
    if (issueRefreshToken) {
      refreshToken = generateRefreshToken(user.id, user.username, expiresIn);
      // Calculate expiration for database storage
      const refreshExpiration = calculateRefreshTokenExpiration(expiresIn);
      const refreshExpirationSeconds = parseExpiresIn(refreshExpiration);
      const refreshExpirationDays = Math.ceil(refreshExpirationSeconds / 86400);
      storeRefreshToken(user.id, refreshToken, refreshExpirationDays);
    }

    const responseData: LoginResponse = {
      user: {
        id: user.id,
        username: user.username,
      },
      accessToken,
      algorithm,
      expiresIn,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    };

    // Only include refreshToken if it was requested and generated
    if (refreshToken) {
      responseData.refreshToken = refreshToken;
    }

    return res.status(200).json({
      message: "Login successful",
      data: responseData,
    });
  } catch (err: any) {
    console.error("Error in login:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * Refresh access token using refresh token
 */
export const refreshToken = async (req: Request<{}, ApiResponse<RefreshTokenResponse>, RefreshTokenRequestBody>, res: Response): Promise<Response> => {
  const { refreshToken: clientRefreshToken, originalExpiresIn } = req.body;

  if (!clientRefreshToken) {
    return res.status(400).json({
      error: "Refresh token is required",
    });
  }

  try {
    // Validate refresh token and get user info
    const userInfo = validateRefreshToken(clientRefreshToken);
    
    if (!userInfo) {
      return res.status(401).json({ error: "Invalid or expired refresh token" });
    }

    // Use original expiration or default to 1h
    const algorithm = 'HS256';
    const expiresIn = originalExpiresIn || '1h';
    
    // Calculate expiration timestamp
    const issuedAt = new Date();
    const expiresAt = calculateExpirationTimestamp(expiresIn);

    // Generate new access token with same expiration as original
    const accessToken = JwtService.sign(
      { 
        userId: userInfo.userId,
        username: userInfo.username,
        type: 'access'
      },
      {
        algorithm,
        expiresIn,
        issuer: "jcoder-api",
      }
    );

    // Rotate refresh token for security
    const newRefreshToken = rotateRefreshToken(clientRefreshToken, userInfo.userId, expiresIn);
    
    if (!newRefreshToken) {
      return res.status(401).json({ error: "Failed to rotate refresh token" });
    }

    return res.status(200).json({
      message: "Tokens refreshed successfully",
      data: {
        accessToken,
        refreshToken: newRefreshToken,
        algorithm,
        expiresIn,
        issuedAt: issuedAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
      },
    });
  } catch (err: any) {
    console.error("Error in refreshToken:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * Logout user by revoking refresh token
 */
export const logout = async (req: Request<{}, ApiResponse, RefreshTokenRequestBody>, res: Response): Promise<Response> => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({
      error: "Refresh token is required",
    });
  }

  try {
    const revoked = revokeRefreshToken(refreshToken);
    
    if (!revoked) {
      return res.status(404).json({ error: "Refresh token not found" });
    }

    return res.status(200).json({
      message: "Logout successful",
    });
  } catch (err: any) {
    console.error("Error in logout:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * Logout from all devices by revoking all refresh tokens for the user
 */
export const logoutAll = async (req: Request, res: Response): Promise<Response> => {
  try {
    // req.user is set by the authenticateToken middleware
    if (!req.user) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const revokedCount = revokeAllUserTokens(req.user.userId);

    return res.status(200).json({
      message: `Logout successful from all devices`,
      data: {
        revokedTokens: revokedCount
      }
    });
  } catch (err: any) {
    console.error("Error in logoutAll:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * Get available JWT algorithms and expiration options
 */
export const getAlgorithms = (req: Request, res: Response): Response => {
  try {
    const availableAlgorithms = JwtService.getAvailableAlgorithms();
    const expirationOptions = getExpirationOptions();
    
    return res.status(200).json({
      message: "Available JWT algorithms and expiration options",
      data: {
        algorithms: availableAlgorithms,
        defaultAlgorithm: "HS256",
        algorithmDescriptions: {
          "HS256": "HMAC using SHA-256 hash algorithm",
          "HS384": "HMAC using SHA-384 hash algorithm", 
          "HS512": "HMAC using SHA-512 hash algorithm",
          "RS256": "RSA using SHA-256 hash algorithm",
          "RS384": "RSA using SHA-384 hash algorithm",
          "RS512": "RSA using SHA-512 hash algorithm"
        },
        expirationOptions,
        defaultExpiration: "24h",
        expirationFormats: {
          "examples": ["5", "10", "15m", "1h", "24h", "7d", "30d"],
          "units": {
            "s": "seconds",
            "m": "minutes", 
            "h": "hours",
            "d": "days",
            "y": "years"
          },
          "note": "Use format: number + unit (e.g., '2h' for 2 hours) or plain numbers for seconds"
        }
      },
    });
  } catch (err: any) {
    console.error("Error in getAlgorithms:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};