// Middleware module barrel export
export { requireAuth } from './auth';
export { requireRole } from './rbac';
export { requirePermissions } from './permissions';
export { AppError, catchAsync, globalErrorHandler } from './errorHandler';
