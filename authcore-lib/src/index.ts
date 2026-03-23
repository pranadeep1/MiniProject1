// ============================================================
// AuthCore - Main Entry Point
// ============================================================
// This is the single public API surface of the authcore library.
// All modules are re-exported from here so consumers can import
// everything from one place:
//
//   import { requireAuth, CryptoService, MongoAuthAdapter } from 'authcore';
//
// ============================================================

// --- Adapter Layer ---
export type {
  AuthDatabaseAdapter,
  UserPayload,
  UserRecord,
} from './adapter/DatabaseAdapter';
export { MongoAuthAdapter } from './adapter/MongoAuthAdapter';
export { UserSchema, RoleSchema, AuditLogSchema } from './adapter/MongoSchemas';

// --- Cryptography ---
export { CryptoService } from './crypto/tokens';
export type { CryptoConfig } from './crypto/tokens';

// --- Express Middleware ---
export { requireAuth } from './middleware/auth';
export { requireRole } from './middleware/rbac';
export { requirePermissions } from './middleware/permissions';
export {
  AppError,
  catchAsync,
  globalErrorHandler,
} from './middleware/errorHandler';

// --- Auth Service (Core Orchestrator) ---
export { AuthService } from './services/AuthService';
export type { AuthServiceConfig } from './services/AuthService';

// --- Type Augmentation (side-effect import) ---
import './types/express.d';
