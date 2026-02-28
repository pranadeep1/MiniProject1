// Middleware module barrel export
export { requireAuth } from './auth';
export { requireRole } from './rbac';
export { AppError, catchAsync, globalErrorHandler } from './errorHandler';
