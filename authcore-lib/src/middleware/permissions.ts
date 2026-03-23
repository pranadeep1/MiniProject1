import { Request, Response, NextFunction } from 'express';

/**
 * requirePermissions checks if an authenticated user has all required permissions.
 */
export const requirePermissions = (requiredPermissions: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }

    const userPermissions = req.user.permissions || [];
    const hasAllPermissions = requiredPermissions.every((permission) =>
      userPermissions.includes(permission)
    );

    if (!hasAllPermissions) {
      res.status(403).json({ error: 'Forbidden: Missing required permissions.' });
      return;
    }

    next();
  };
};
