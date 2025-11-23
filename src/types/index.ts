// Request body types
export interface SignupRequestBody {
  username: string;
  password: string;
  secretMessage: string;
}

export interface LoginRequestBody {
  username: string;
  password: string;
  algorithm?: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512';
  expiresIn?: string;
  issueRefreshToken?: boolean;
}

// Response types
export interface UserResponse {
  username: string;
  secretMessage: string;
  createdAt: string;
}

export interface LoginResponse {
  user: {
    id: number;
    username: string;
  };
  accessToken: string;
  refreshToken?: string;
  algorithm: string;
  expiresIn: string;
  issuedAt: string;
  expiresAt: string;
}

export interface RefreshTokenRequestBody {
  refreshToken: string;
  originalExpiresIn?: string;
}

export interface RefreshTokenResponse {
  accessToken: string;
  refreshToken: string;
  algorithm: string;
  expiresIn: string;
  issuedAt: string;
  expiresAt: string;
}

export interface SecretMessageResponse {
  secretMessage: string;
  username: string;
  createdAt: string;
  retrievedAt: string;
}

export interface ApiResponse<T = any> {
  message?: string;
  error?: string;
  data?: T;
}

// Database types
export interface User {
  id: number;
  username: string;
  password_hash: string;
  secret_message: string;
  created_at: string;
}

export interface RefreshToken {
  id: number;
  user_id: number;
  token_hash: string;
  expires_at: string;
  created_at: string;
}