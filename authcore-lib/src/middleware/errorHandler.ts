// ============================================================
// AuthCore - Asynchronous Error Handling
// ============================================================
// Custom error classes and middleware wrappers to catch all
// asynchronous exceptions and forward them to Express's
// global error handler via the next(err) function.
// ============================================================

import { Request, Response, NextFunction } from 'express';

// -----------------------------------------------------------
// Custom Application Error Class
// -----------------------------------------------------------

/**
 * AppError — Base error class for the AuthCore library.
 *
 * Encapsulates HTTP status codes alongside error messages,
 * allowing the global handler to send the correct response.
 */
export class AppError extends Error {
  public statusCode: number;
  public isOperational: boolean;

  constructor(statusCode: number, message: string) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true; // Distinguishes known errors from unexpected crashes

    // Ensure instanceof checks work correctly with ES6 classes
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// -----------------------------------------------------------
// Async Wrapper
// -----------------------------------------------------------

/**
 * catchAsync — Wraps an async Express handler to catch rejections.
 *
 * Express 4 does not natively catch promise rejections.
 * This wrapper ensures any thrown error is forwarded to next().
 *
 * Usage:
 *   app.get('/route', catchAsync(async (req, res, next) => { ... }));
 */
export const catchAsync = (
  fn: (req: Request, res: Response, next: NextFunction) => Promise<any>
) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// -----------------------------------------------------------
// Global Error Handler
// -----------------------------------------------------------

/**
 * globalErrorHandler — Express error-handling middleware.
 *
 * Express identifies this as an error handler by its strict
 * four-parameter signature: (err, req, res, next).
 *
 * Differentiates between operational (known) errors and
 * unexpected programming errors.
 */
export const globalErrorHandler = (
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const statusCode = err.statusCode || 500;
  const message = err.isOperational
    ? err.message
    : 'An unexpected internal server error occurred.';

  res.status(statusCode).json({
    status: 'error',
    statusCode,
    message,
  });
};
