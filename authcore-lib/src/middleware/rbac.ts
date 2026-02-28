// ============================================================
// AuthCore - Role-Based Access Control (RBAC) Middleware
// ============================================================
// Centralized policy engine that evaluates user roles against
// explicitly required permissions at the middleware layer.
// ============================================================

import { Request, Response, NextFunction } from 'express';

/**
 * requireRole — Middleware factory for role-based authorization.
 *
 * Must be placed AFTER `requireAuth` in the middleware chain,
 * as it depends on `req.user` being populated.
 *
 * @param allowedRoles - Array of role strings permitted to access the route.
 * @returns Express middleware function.
 *
 * Usage:
 *   app.delete('/admin/resource',
 *     requireAuth(JWT_SECRET),
 *     requireRole(['ADMIN', 'SUPERADMIN']),
 *     handler
 *   );
 */
export const requireRole = (allowedRoles: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    // Failsafe: ensure requireAuth was called before this middleware
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({ error: 'Forbidden: Insufficient permissions.' });
      return;
    }

    next();
  };
};
