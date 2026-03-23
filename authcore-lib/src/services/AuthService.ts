// ============================================================
// AuthCore - Authentication Service (Core Orchestrator)
// ============================================================
// This is the central service that ties together the database
// adapter, cryptography service, and security policies into
// concrete authentication flows:
//   - Register (hash password, persist user)
//   - Login    (verify credentials, issue token pair)
//   - Refresh  (Refresh Token Rotation — RTR)
//   - Logout   (revoke refresh token)
// ============================================================

import { Request, Response } from 'express';
import {
  AuthDatabaseAdapter,
  RefreshSessionRecord,
  UserPayload,
} from '../adapter/DatabaseAdapter';
import { CryptoService, CryptoConfig } from '../crypto/tokens';
import { AppError } from '../middleware/errorHandler';

/**
 * Configuration for the AuthService.
 */
export interface AuthServiceConfig extends CryptoConfig {
  cookieName?: string;          // Name of the HTTP-Only cookie (default: 'refreshToken')
  secureCookies?: boolean;      // Set Secure flag on cookies (default: true in production)
  maxFailedLoginAttempts?: number;
  lockoutMs?: number;
}

/**
 * AuthService — Orchestrates all authentication workflows.
 *
 * This class is the primary interface that consuming applications
 * interact with. It combines the database adapter and crypto service
 * to implement complete auth flows with security best practices.
 */
export class AuthService {
  private crypto: CryptoService;
  private adapter: AuthDatabaseAdapter;
  private cookieName: string;
  private secureCookies: boolean;
  private maxFailedLoginAttempts: number;
  private lockoutMs: number;

  constructor(adapter: AuthDatabaseAdapter, config: AuthServiceConfig) {
    this.adapter = adapter;
    this.crypto = new CryptoService(config);
    this.cookieName = config.cookieName || 'refreshToken';
    this.secureCookies = config.secureCookies ?? (process.env.NODE_ENV === 'production');
    this.maxFailedLoginAttempts = config.maxFailedLoginAttempts ?? 5;
    this.lockoutMs = config.lockoutMs ?? 15 * 60 * 1000;
  }

  // -----------------------------------------------------------
  // LOGIN
  // -----------------------------------------------------------

  /**
   * Authenticates a user by email and password.
   *
   * Flow:
   * 1. Retrieve user record from DB via adapter
   * 2. Compare submitted password against stored bcrypt hash
   * 3. Generate access token (short-lived, returned in JSON body)
   * 4. Generate refresh token (long-lived, set in HTTP-Only cookie)
   * 5. Hash the refresh token and persist it in the DB for RTR tracking
   */
  async login(email: string, password: string, req: Request, res: Response) {
    // Step 1: Find user
    const user = await this.adapter.getUserByEmail(email);
    if (!user) {
      throw new AppError(401, 'Invalid email or password.');
    }

    if (user.lockUntil && new Date(user.lockUntil).getTime() > Date.now()) {
      throw new AppError(429, 'Account temporarily locked due to too many failed login attempts.');
    }

    if (user.emailVerified === false) {
      throw new AppError(403, 'Email not verified. Please verify OTP before login.');
    }

    // Step 2: Verify password
    const isMatch = await this.crypto.compareData(password, user.password);
    if (!isMatch) {
      const lockState = await this.adapter.incrementFailedLoginAttempts(
        user.id,
        this.maxFailedLoginAttempts,
        this.lockoutMs
      );
      if (lockState.lockUntil) {
        throw new AppError(429, 'Account temporarily locked due to too many failed login attempts.');
      }
      throw new AppError(401, 'Invalid email or password.');
    }

    await this.adapter.clearLoginFailures(user.id);

    // Step 3 & 4: Generate token pair
    const payload: UserPayload = {
      id: user.id,
      role: user.role,
      email: user.email,
      permissions: user.permissions || [],
    };
    const accessToken = this.crypto.generateAccessToken(payload);
    const refreshToken = this.crypto.generateRefreshToken(payload);

    // Step 5: Hash and store the refresh token for RTR
    const hashedRefreshToken = await this.crypto.hashData(refreshToken);
    await this.adapter.saveRefreshToken(user.id, hashedRefreshToken, {
      userAgent: req.headers['user-agent'],
      ip: req.ip,
    });

    // Set refresh token in HTTP-Only cookie
    this.setRefreshCookie(res, refreshToken);

    return { accessToken, user: payload };
  }

  // -----------------------------------------------------------
  // REFRESH TOKEN (with Rotation)
  // -----------------------------------------------------------

  /**
   * Issues a new access/refresh token pair using Refresh Token Rotation.
   *
   * Flow:
   * 1. Extract refresh token from HTTP-Only cookie
   * 2. Verify the refresh token JWT signature
   * 3. Look up the user and find the matching hashed token in DB
   * 4. Revoke the old refresh token (rotation)
   * 5. Issue a new token pair and persist the new refresh token hash
   *
   * If step 3 fails (token not found in DB), it means a previously
   * rotated token was reused — a sign of potential theft.
   * We revoke ALL tokens for that user as a security measure.
   */
  async refreshToken(req: Request, res: Response) {
    const token = req.cookies?.[this.cookieName];
    if (!token) {
      throw new AppError(401, 'Refresh token missing.');
    }

    // Verify JWT signature
    let decoded: UserPayload;
    try {
      decoded = this.crypto.verifyRefreshToken(token);
    } catch {
      this.clearRefreshCookie(res);
      throw new AppError(401, 'Invalid or expired refresh token.');
    }

    // Look up user to validate the token still exists in DB
    const user = await this.adapter.getUserByEmail(decoded.email);
    if (!user) {
      throw new AppError(401, 'User no longer exists.');
    }

    const sessions = await this.adapter.getRefreshSessions(user.id);
    const matchingSession = await this.findMatchingSession(sessions, token);

    if (!matchingSession) {
      await this.adapter.revokeAllRefreshTokens(user.id);
      this.clearRefreshCookie(res);
      throw new AppError(401, 'Refresh token reuse detected. Sessions revoked.');
    }

    // Rotate only the matching session for better multi-device UX.
    await this.adapter.revokeRefreshSession(user.id, matchingSession.id);

    // Issue new token pair
    const payload: UserPayload = {
      id: user.id,
      role: user.role,
      email: user.email,
      permissions: user.permissions || [],
    };
    const newAccessToken = this.crypto.generateAccessToken(payload);
    const newRefreshToken = this.crypto.generateRefreshToken(payload);

    // Persist the new hashed refresh token
    const hashedNewToken = await this.crypto.hashData(newRefreshToken);
    await this.adapter.saveRefreshToken(user.id, hashedNewToken, {
      userAgent: req.headers['user-agent'],
      ip: req.ip,
    });

    // Set the new refresh token cookie
    this.setRefreshCookie(res, newRefreshToken);

    return { accessToken: newAccessToken, user: payload };
  }

  // -----------------------------------------------------------
  // LOGOUT
  // -----------------------------------------------------------

  /**
   * Logs out the user by revoking all refresh tokens and clearing the cookie.
   */
  async logout(req: Request, res: Response) {
    const token = req.cookies?.[this.cookieName];

    if (token) {
      try {
        const decoded = this.crypto.verifyRefreshToken(token);
        const sessions = await this.adapter.getRefreshSessions(decoded.id);
        const matchingSession = await this.findMatchingSession(sessions, token);
        if (matchingSession) {
          await this.adapter.revokeRefreshSession(decoded.id, matchingSession.id);
        }
      } catch {
        // Token invalid/expired — just clear the cookie anyway
      }
    }

    this.clearRefreshCookie(res);
    return { message: 'Logged out successfully.' };
  }

  /**
   * Returns active user sessions (without hashed tokens).
   */
  async listSessions(userId: string) {
    const sessions = await this.adapter.getRefreshSessions(userId);
    return sessions.map((s) => ({
      id: s.id,
      userAgent: s.userAgent,
      ip: s.ip,
      createdAt: s.createdAt,
      lastUsedAt: s.lastUsedAt,
    }));
  }

  /**
   * Revoke a single active session.
   */
  async revokeSession(userId: string, sessionId: string) {
    await this.adapter.revokeRefreshSession(userId, sessionId);
    return { message: 'Session revoked successfully.' };
  }

  // -----------------------------------------------------------
  // Cookie Helpers
  // -----------------------------------------------------------

  /**
   * Sets the refresh token in a secure HTTP-Only cookie.
   * - httpOnly: Prevents JavaScript access (XSS mitigation)
   * - secure:   Only sent over HTTPS
   * - sameSite: Prevents CSRF attacks
   */
  private setRefreshCookie(res: Response, token: string): void {
    res.cookie(this.cookieName, token, {
      httpOnly: true,
      secure: this.secureCookies,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
      path: '/',
    });
  }

  /**
   * Clears the refresh token cookie.
   */
  private clearRefreshCookie(res: Response): void {
    res.clearCookie(this.cookieName, {
      httpOnly: true,
      secure: this.secureCookies,
      sameSite: 'strict',
      path: '/',
    });
  }

  private async findMatchingSession(
    sessions: RefreshSessionRecord[],
    token: string
  ): Promise<RefreshSessionRecord | null> {
    for (const session of sessions) {
      const isMatch = await this.crypto.compareData(token, session.hashedToken);
      if (isMatch) {
        return session;
      }
    }
    return null;
  }
}
