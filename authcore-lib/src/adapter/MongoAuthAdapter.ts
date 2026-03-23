// ============================================================
// AuthCore - MongoDB/Mongoose Adapter Implementation
// ============================================================
// Concrete implementation of the AuthDatabaseAdapter interface
// using Mongoose. This bridges the library's abstract data
// operations with MongoDB-specific queries.
// ============================================================

import { Model, Types } from 'mongoose';
import {
  AuthDatabaseAdapter,
  RefreshSessionRecord,
  UserRecord,
} from './DatabaseAdapter';

/**
 * MongoAuthAdapter — Implements AuthDatabaseAdapter for MongoDB.
 *
 * The consuming application passes in a compiled Mongoose model,
 * and this adapter translates the library's data requests into
 * Mongoose queries.
 */
export class MongoAuthAdapter implements AuthDatabaseAdapter {
  constructor(private UserModel: Model<any>) {}

  async getUserByEmail(email: string): Promise<UserRecord | null> {
    const user = await this.UserModel.findOne({ email }).lean();
    if (!user) return null;

    return {
      id: (user as any)._id.toString(),
      role: (user as any).role,
      email: (user as any).email,
      password: (user as any).password,
      emailVerified: (user as any).emailVerified ?? true,
      permissions: (user as any).permissions || [],
      failedLoginAttempts: (user as any).failedLoginAttempts || 0,
      lockUntil: (user as any).lockUntil || null,
      refreshSessions: ((user as any).refreshSessions || []).map((s: any) => ({
        id: s._id.toString(),
        hashedToken: s.hashedToken,
        userAgent: s.userAgent,
        ip: s.ip,
        createdAt: s.createdAt,
        lastUsedAt: s.lastUsedAt,
      })),
    };
  }

  async saveRefreshToken(
    userId: string,
    hashedToken: string,
    metadata?: { userAgent?: string; ip?: string }
  ): Promise<string> {
    const sessionId = new Types.ObjectId();
    await this.UserModel.findByIdAndUpdate(userId, {
      $push: {
        refreshSessions: {
          _id: sessionId,
          hashedToken,
          userAgent: metadata?.userAgent,
          ip: metadata?.ip,
          createdAt: new Date(),
          lastUsedAt: new Date(),
        },
      },
    });
    return sessionId.toString();
  }

  async revokeRefreshToken(userId: string, hashedToken: string): Promise<void> {
    await this.UserModel.findByIdAndUpdate(userId, {
      $pull: { refreshSessions: { hashedToken } },
    });
  }

  async revokeRefreshSession(userId: string, sessionId: string): Promise<void> {
    await this.UserModel.findByIdAndUpdate(userId, {
      $pull: { refreshSessions: { _id: sessionId } },
    });
  }

  async getRefreshSessions(userId: string): Promise<RefreshSessionRecord[]> {
    const user = await this.UserModel.findById(userId)
      .select('refreshSessions')
      .lean();

    const sessions = (user as any)?.refreshSessions || [];
    return sessions.map((s: any) => ({
      id: s._id.toString(),
      hashedToken: s.hashedToken,
      userAgent: s.userAgent,
      ip: s.ip,
      createdAt: s.createdAt,
      lastUsedAt: s.lastUsedAt,
    }));
  }

  async touchRefreshSession(userId: string, sessionId: string): Promise<void> {
    await this.UserModel.updateOne(
      { _id: userId, 'refreshSessions._id': sessionId },
      { $set: { 'refreshSessions.$.lastUsedAt': new Date() } }
    );
  }

  async revokeAllRefreshTokens(userId: string): Promise<void> {
    await this.UserModel.findByIdAndUpdate(userId, {
      $set: { refreshSessions: [] },
    });
  }

  async incrementFailedLoginAttempts(
    userId: string,
    maxAttempts: number,
    lockMs: number
  ): Promise<{ failedLoginAttempts: number; lockUntil: Date | null }> {
    const user = await this.UserModel.findById(userId)
      .select('failedLoginAttempts')
      .lean();

    const currentAttempts = ((user as any)?.failedLoginAttempts || 0) + 1;
    const shouldLock = currentAttempts >= maxAttempts;
    const lockUntil = shouldLock ? new Date(Date.now() + lockMs) : null;

    await this.UserModel.findByIdAndUpdate(userId, {
      $set: {
        failedLoginAttempts: currentAttempts,
        lockUntil,
      },
    });

    return { failedLoginAttempts: currentAttempts, lockUntil };
  }

  async clearLoginFailures(userId: string): Promise<void> {
    await this.UserModel.findByIdAndUpdate(userId, {
      $set: {
        failedLoginAttempts: 0,
        lockUntil: null,
      },
    });
  }
}
