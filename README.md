# jcoder - JWT Authentication API

A complete JWT-based authentication system built with TypeScript, Express.js, and SQLite.

## Features

### Authentication
- User signup and login with JWT tokens
- Multiple JWT algorithms support (HMAC: HS256/384/512, RSA: RS256/384/512)
- Customizable token expiration duration
- Optional refresh token functionality
- Secure password hashing with scrypt
- Protected routes with JWT middleware

### JWT Library
- Custom JWT implementation from scratch
- Support for both HMAC and RSA algorithms
- Base64URL encoding/decoding utilities
- Comprehensive token validation

### Database
- SQLite database with users and refresh_tokens tables
- Automatic database initialization
- Proper indexing and foreign key constraints

## Refresh Token System

The API implements a secure refresh token system with the following features:

### Key Features
- **Optional Refresh Tokens**: Only issued when `issueRefreshToken: true` is provided during login
- **Separate Secret**: Refresh tokens are signed with a different secret (`REFRESH_TOKEN_SECRET`) than access tokens
- **Smart Expiration**: Refresh tokens expire 30x longer than access tokens, with a minimum of 30 minutes
- **JWT-based**: Refresh tokens are proper JWT tokens, not random strings
- **Token Rotation**: Refresh tokens are rotated on each use for enhanced security
- **Database Tracking**: Tokens are stored in the database for revocation support

### ⏱️ Expiration Logic
- If access token expires in 1 hour → refresh token expires in 30 hours
- If access token expires in 15 minutes → refresh token expires in 30 minutes (minimum)
- If access token expires in 24 hours → refresh token expires in 30 days

### Security Features
- Refresh tokens use `HS256` algorithm with separate secret
- Token hashes stored in database for secure validation
- Automatic cleanup of expired tokens
- Multi-device logout support
- Token rotation prevents replay attacks

### Environment Variables
```env
JWT_SECRET='your-access-token-secret'
REFRESH_TOKEN_SECRET='your-refresh-token-secret'
```

## API Endpoints

### Authentication Routes (`/api/auth`)
- `POST /signup` - Register a new user
- `POST /login` - Authenticate user and get access token
- `POST /refresh` - Refresh access token using refresh token
- `POST /logout` - Logout from current device
- `POST /logout-all` - Logout from all devices
- `GET /algorithms` - Get available JWT algorithms

### User Routes (`/api/user`)
- `GET /secret` - Get protected secret message (requires authentication)

## Usage

### Login with Optional Refresh Token
```json
POST /api/auth/login
{
  "username": "john_doe",
  "password": "securePassword123",
  "algorithm": "HS256",
  "expiresIn": "1h",
  "issueRefreshToken": true
}
```

**Note:** Set `issueRefreshToken: true` in the login request to receive a refresh token. If not specified or set to `false`, only an access token will be issued.

## Setup

- nvm install 23
- nvm use 23
- npm install
- npm run dev

### TODO

- [x] HMAC
- [x] Utils Segregation
- [x] RSA
- [x] API Expose
  - [x] Database for storing users' credentials and secret message for testing purposes
  - [x] Secret message route
- [x] Refresh Token Functionality
  - [x] Optional refresh token issuance based on user preference
- [ ] Frontend Setup
- [ ] Frontend Integration
