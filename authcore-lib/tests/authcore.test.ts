import { describe, it, expect, vi } from 'vitest';
import jwt from 'jsonwebtoken';
import { CryptoService } from '../src/crypto/tokens';
import { requireAuth } from '../src/middleware/auth';
import { requireRole } from '../src/middleware/rbac';
import {
  AppError,
  catchAsync,
  globalErrorHandler,
} from '../src/middleware/errorHandler';
import { MongoAuthAdapter } from '../src/adapter/MongoAuthAdapter';
import { UserPayload } from '../src/adapter/DatabaseAdapter';

const ACCESS_SECRET = 'test-access-secret';
const REFRESH_SECRET = 'test-refresh-secret';

const createMockResponse = () => {
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res;
};

describe('AuthCore Library', () => {
  describe('CryptoService', () => {
    it('hashes data and verifies it correctly', async () => {
      const crypto = new CryptoService({
        accessTokenSecret: ACCESS_SECRET,
        refreshTokenSecret: REFRESH_SECRET,
      });

      const hash = await crypto.hashData('password123');
      const isMatch = await crypto.compareData('password123', hash);

      expect(isMatch).toBe(true);
    });

    it('generates and verifies a valid access token', () => {
      const crypto = new CryptoService({
        accessTokenSecret: ACCESS_SECRET,
        refreshTokenSecret: REFRESH_SECRET,
      });

      const payload: UserPayload = { id: '1', role: 'USER', email: 'user@test.com' };
      const token = crypto.generateAccessToken(payload);
      const decoded = crypto.verifyAccessToken(token);

      expect(decoded.id).toBe(payload.id);
      expect(decoded.role).toBe(payload.role);
      expect(decoded.email).toBe(payload.email);
    });

    it('rejects an expired access token', async () => {
      const crypto = new CryptoService({
        accessTokenSecret: ACCESS_SECRET,
        refreshTokenSecret: REFRESH_SECRET,
        accessTokenExpiry: '1ms',
      });

      const payload: UserPayload = { id: '1', role: 'USER', email: 'user@test.com' };
      const token = crypto.generateAccessToken(payload);

      await new Promise((resolve) => setTimeout(resolve, 10));
      expect(() => crypto.verifyAccessToken(token)).toThrow();
    });

    it('rejects a tampered token', () => {
      const crypto = new CryptoService({
        accessTokenSecret: ACCESS_SECRET,
        refreshTokenSecret: REFRESH_SECRET,
      });

      const payload: UserPayload = { id: '1', role: 'USER', email: 'user@test.com' };
      const token = crypto.generateAccessToken(payload);
      const tampered = `${token}tampered`;

      expect(() => crypto.verifyAccessToken(tampered)).toThrow();
    });
  });

  describe('requireAuth Middleware', () => {
    it('returns 401 if no token is provided', () => {
      const middleware = requireAuth(ACCESS_SECRET);
      const req: any = { headers: {} };
      const res = createMockResponse();
      const next = vi.fn();

      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('returns 401 if token is invalid', () => {
      const middleware = requireAuth(ACCESS_SECRET);
      const req: any = { headers: { authorization: 'Bearer invalid-token' } };
      const res = createMockResponse();
      const next = vi.fn();

      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('attaches user payload to req.user on valid token', () => {
      const middleware = requireAuth(ACCESS_SECRET);
      const payload: UserPayload = { id: '1', role: 'USER', email: 'user@test.com' };
      const token = jwt.sign(payload, ACCESS_SECRET);

      const req: any = { headers: { authorization: `Bearer ${token}` } };
      const res = createMockResponse();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      expect(req.user.id).toBe(payload.id);
      expect(req.user.role).toBe(payload.role);
      expect(req.user.email).toBe(payload.email);
    });
  });

  describe('requireRole Middleware', () => {
    it('returns 401 if req.user is not set', () => {
      const middleware = requireRole(['ADMIN']);
      const req: any = {};
      const res = createMockResponse();
      const next = vi.fn();

      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('returns 403 if user role is not in allowedRoles', () => {
      const middleware = requireRole(['ADMIN']);
      const req: any = { user: { id: '1', email: 'user@test.com', role: 'USER' } };
      const res = createMockResponse();
      const next = vi.fn();

      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });

    it('calls next() if user role is permitted', () => {
      const middleware = requireRole(['ADMIN']);
      const req: any = { user: { id: '1', email: 'admin@test.com', role: 'ADMIN' } };
      const res = createMockResponse();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
    });
  });

  describe('Error Handling', () => {
    it('creates AppError with correct statusCode and message', () => {
      const err = new AppError(400, 'Bad request');

      expect(err.statusCode).toBe(400);
      expect(err.message).toBe('Bad request');
      expect(err.isOperational).toBe(true);
    });

    it('catchAsync forwards async errors to next()', async () => {
      const expectedError = new AppError(401, 'Unauthorized');
      const handler = catchAsync(async () => {
        throw expectedError;
      });

      const req: any = {};
      const res = createMockResponse();
      const next = vi.fn();

      handler(req, res, next);
      await new Promise((resolve) => setImmediate(resolve));

      expect(next).toHaveBeenCalledWith(expectedError);
    });

    it('globalErrorHandler returns structured JSON error', () => {
      const err = new AppError(404, 'Not found');
      const req: any = {};
      const res = createMockResponse();
      const next = vi.fn();

      globalErrorHandler(err, req, res, next);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({
        status: 'error',
        statusCode: 404,
        message: 'Not found',
      });
    });
  });

  describe('MongoAuthAdapter', () => {
    it('returns a user record by email', async () => {
      const dbUser = {
        _id: { toString: () => 'mongo-id-1' },
        role: 'USER',
        email: 'user@test.com',
        password: 'hashed',
      };

      const UserModel: any = {
        findOne: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue(dbUser) }),
      };

      const adapter = new MongoAuthAdapter(UserModel);
      const user = await adapter.getUserByEmail('user@test.com');

      expect(user).toEqual({
        id: 'mongo-id-1',
        role: 'USER',
        email: 'user@test.com',
        password: 'hashed',
      });
    });

    it('returns null for non-existent email', async () => {
      const UserModel: any = {
        findOne: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue(null) }),
      };

      const adapter = new MongoAuthAdapter(UserModel);
      const user = await adapter.getUserByEmail('missing@test.com');

      expect(user).toBeNull();
    });

    it('save/revoke token methods call the expected DB updates', async () => {
      const UserModel: any = {
        findByIdAndUpdate: vi.fn().mockResolvedValue(null),
      };

      const adapter = new MongoAuthAdapter(UserModel);
      await adapter.saveRefreshToken('u1', 'hash-1');
      await adapter.revokeRefreshToken('u1', 'hash-1');
      await adapter.revokeAllRefreshTokens('u1');

      expect(UserModel.findByIdAndUpdate).toHaveBeenNthCalledWith(1, 'u1', {
        $push: { refreshTokens: 'hash-1' },
      });
      expect(UserModel.findByIdAndUpdate).toHaveBeenNthCalledWith(2, 'u1', {
        $pull: { refreshTokens: 'hash-1' },
      });
      expect(UserModel.findByIdAndUpdate).toHaveBeenNthCalledWith(3, 'u1', {
        $set: { refreshTokens: [] },
      });
    });
  });
});
