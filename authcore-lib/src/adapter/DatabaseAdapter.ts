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
}

/**
 * The raw user record as stored in the database.
 * Extends UserPayload with the hashed password field,
 * which is never exposed in tokens or API responses.
 */
export interface UserRecord extends UserPayload {
  password: string;
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
  saveRefreshToken(userId: string, hashedToken: string): Promise<void>;

  /**
   * Revoke (delete) a specific hashed refresh token for a user.
   * Used during Refresh Token Rotation (RTR) and logout flows.
   */
  revokeRefreshToken(userId: string, hashedToken: string): Promise<void>;

  /**
   * Revoke ALL refresh tokens for a user.
   * Used as a security measure when a compromised token is detected.
   */
  revokeAllRefreshTokens(userId: string): Promise<void>;
}
