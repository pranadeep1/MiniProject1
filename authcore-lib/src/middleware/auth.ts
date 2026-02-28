// ============================================================
// AuthCore - Authentication Middleware
// ============================================================
// Express middleware for verifying JWTs and attaching the
// decoded user payload to the request object.
// ============================================================

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { UserPayload } from '../adapter/DatabaseAdapter';

/**
 * requireAuth — Middleware factory that protects routes.
 *
 * Extracts the Bearer token from the Authorization header,
 * verifies it, and attaches the decoded UserPayload to `req.user`.
 *
 * @param secret - The JWT secret used to verify the access token.
 * @returns Express middleware function.
 *
 * Usage:
 *   app.get('/protected', requireAuth(JWT_SECRET), handler);
 */
export const requireAuth = (secret: string) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1];

    if (!token) {
      res.status(401).json({ error: 'Authentication required. Token missing.' });
      return;
    }

    try {
      const decoded = jwt.verify(token, secret) as UserPayload;
      req.user = decoded;
      next();
    } catch (err) {
      res.status(401).json({ error: 'Invalid or expired access token.' });
      return;
    }
  };
};
