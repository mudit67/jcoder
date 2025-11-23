// Request body types
export interface SignupRequestBody {
  username: string;
  password: string;
  secretMessage: string;
}

// Response types
export interface UserResponse {
  username: string;
  secretMessage: string;
  createdAt: string;
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