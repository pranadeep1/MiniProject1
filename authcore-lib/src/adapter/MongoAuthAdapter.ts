// ============================================================
// AuthCore - MongoDB/Mongoose Adapter Implementation
// ============================================================
// Concrete implementation of the AuthDatabaseAdapter interface
// using Mongoose. This bridges the library's abstract data
// operations with MongoDB-specific queries.
// ============================================================

import { Model } from 'mongoose';
import { AuthDatabaseAdapter, UserRecord } from './DatabaseAdapter';

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
    };
  }

  async saveRefreshToken(userId: string, hashedToken: string): Promise<void> {
    await this.UserModel.findByIdAndUpdate(userId, {
      $push: { refreshTokens: hashedToken },
    });
  }

  async revokeRefreshToken(userId: string, hashedToken: string): Promise<void> {
    await this.UserModel.findByIdAndUpdate(userId, {
      $pull: { refreshTokens: hashedToken },
    });
  }

  async revokeAllRefreshTokens(userId: string): Promise<void> {
    await this.UserModel.findByIdAndUpdate(userId, {
      $set: { refreshTokens: [] },
    });
  }
}
