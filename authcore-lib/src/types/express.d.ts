// ============================================================
// AuthCore - Express Request Type Augmentation
// ============================================================
// Uses TypeScript declaration merging to extend the Express
// Request interface globally with the custom `user` property.
// This allows `req.user` to be fully typed across the entire
// consuming application without manual casting.
// ============================================================

import { UserPayload } from '../adapter/DatabaseAdapter';

declare global {
  namespace Express {
    interface Request {
      /**
       * The authenticated user's payload, populated by the
       * `requireAuth` middleware after successful JWT verification.
       */
      user?: UserPayload;
    }
  }
}
