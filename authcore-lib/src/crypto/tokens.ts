// ============================================================
// AuthCore - Cryptography & Token Service
// ============================================================
// Handles all security-sensitive operations:
//   - Password hashing with bcrypt (salted)
//   - Access Token generation (short-lived JWT)
//   - Refresh Token generation (long-lived JWT)
//   - Token verification
// ============================================================

import jwt, { SignOptions } from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { UserPayload } from '../adapter/DatabaseAdapter';

/**
 * Configuration options for the CryptoService.
 */
export interface CryptoConfig {
  accessTokenSecret: string;
  refreshTokenSecret: string;
  accessTokenExpiry?: string;   // Default: '15m'
  refreshTokenExpiry?: string;  // Default: '7d'
  saltRounds?: number;          // Default: 10
}

/**
 * CryptoService — Centralized cryptography and token management.
 *
 * Encapsulates all hashing and JWT operations so that no other
 * module in the library directly interacts with bcrypt or jsonwebtoken.
 */
export class CryptoService {
  private accessTokenSecret: string;
  private refreshTokenSecret: string;
  private accessTokenExpiry: string;
  private refreshTokenExpiry: string;
  private saltRounds: number;

  constructor(config: CryptoConfig) {
    this.accessTokenSecret = config.accessTokenSecret;
    this.refreshTokenSecret = config.refreshTokenSecret;
    this.accessTokenExpiry = config.accessTokenExpiry || '15m';
    this.refreshTokenExpiry = config.refreshTokenExpiry || '7d';
    this.saltRounds = config.saltRounds || 10;
  }

  // -----------------------------------------------------------
  // JWT Operations
  // -----------------------------------------------------------

  /**
   * Generate a short-lived access token containing the user payload.
   */
  generateAccessToken(payload: UserPayload): string {
    const options: SignOptions = {
      expiresIn: this.accessTokenExpiry as any,
    };
    return jwt.sign(payload, this.accessTokenSecret, options);
  }

  /**
   * Generate a long-lived refresh token containing the user payload.
   */
  generateRefreshToken(payload: UserPayload): string {
    const options: SignOptions = {
      expiresIn: this.refreshTokenExpiry as any,
    };
    return jwt.sign(payload, this.refreshTokenSecret, options);
  }

  /**
   * Verify and decode an access token.
   * Throws an error if the token is invalid or expired.
   */
  verifyAccessToken(token: string): UserPayload {
    return jwt.verify(token, this.accessTokenSecret) as UserPayload;
  }

  /**
   * Verify and decode a refresh token.
   * Throws an error if the token is invalid or expired.
   */
  verifyRefreshToken(token: string): UserPayload {
    return jwt.verify(token, this.refreshTokenSecret) as UserPayload;
  }

  // -----------------------------------------------------------
  // Hashing Operations (bcrypt)
  // -----------------------------------------------------------

  /**
   * Hash a plain-text string (password or token) using bcrypt.
   */
  async hashData(data: string): Promise<string> {
    return bcrypt.hash(data, this.saltRounds);
  }

  /**
   * Compare a plain-text string against a bcrypt hash.
   * Returns true if they match.
   */
  async compareData(data: string, hash: string): Promise<boolean> {
    return bcrypt.compare(data, hash);
  }
}
