// ============================================================
// AuthCore - Database Adapter Interface
// ============================================================
// This interface defines the contract that any database adapter
// must fulfill. The consuming application implements this
// interface for their specific database (MongoDB, PostgreSQL, etc.)
// ============================================================

/**
 * Represents the authenticated user's data payload
 * that will be embedded in the JWT and attached to the Express request.
 */
export interface UserPayload {
  id: string;
  role: string;
  email: string;
  permissions?: string[];
}

/**
 * Metadata captured for each refresh-token-backed session.
 */
export interface RefreshSessionRecord {
  id: string;
  hashedToken: string;
  userAgent?: string;
  ip?: string;
  createdAt: Date;
  lastUsedAt: Date;
}

/**
 * The raw user record as stored in the database.
 * Extends UserPayload with the hashed password field,
 * which is never exposed in tokens or API responses.
 */
export interface UserRecord extends UserPayload {
  password: string;
  emailVerified?: boolean;
  failedLoginAttempts?: number;
  lockUntil?: Date | null;
  refreshSessions?: RefreshSessionRecord[];
}

/**
 * AuthDatabaseAdapter — Abstract interface for data persistence.
 *
 * Any class implementing this adapter must provide concrete
 * implementations of the following methods. This is the core
 * of the Adapter Design Pattern used in AuthCore.
 */
export interface AuthDatabaseAdapter {
  /**
   * Retrieve a user record (including hashed password) by email.
   * Used during the login/authentication flow.
   */
  getUserByEmail(email: string): Promise<UserRecord | null>;

  /**
   * Persist a hashed refresh token associated with a user.
   * Used during login and token refresh flows.
   */
  saveRefreshToken(
    userId: string,
    hashedToken: string,
    metadata?: { userAgent?: string; ip?: string }
  ): Promise<string>;

  /**
   * Revoke (delete) a specific hashed refresh token for a user.
   * Used during Refresh Token Rotation (RTR) and logout flows.
   */
  revokeRefreshToken(userId: string, hashedToken: string): Promise<void>;

  /**
   * Revoke (delete) one refresh session by session id.
   */
  revokeRefreshSession(userId: string, sessionId: string): Promise<void>;

  /**
   * Return all refresh sessions for a user.
   */
  getRefreshSessions(userId: string): Promise<RefreshSessionRecord[]>;

  /**
   * Update the activity timestamp for a session.
   */
  touchRefreshSession(userId: string, sessionId: string): Promise<void>;

  /**
   * Revoke ALL refresh tokens for a user.
   * Used as a security measure when a compromised token is detected.
   */
  revokeAllRefreshTokens(userId: string): Promise<void>;

  /**
   * Increment failed attempts and set lockUntil when max attempts reached.
   */
  incrementFailedLoginAttempts(
    userId: string,
    maxAttempts: number,
    lockMs: number
  ): Promise<{ failedLoginAttempts: number; lockUntil: Date | null }>;

  /**
   * Clear lockout state on successful login.
   */
  clearLoginFailures(userId: string): Promise<void>;
}
