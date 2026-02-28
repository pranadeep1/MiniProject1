// ============================================================
// AuthCore - Mongoose Schemas
// ============================================================
// Exports raw Mongoose schemas (NOT compiled models).
// This allows consuming applications to compile the models
// using their own connection instances, supporting flexible
// connection patterns (e.g., multiple databases, replica sets).
// ============================================================

import { Schema } from 'mongoose';

/**
 * UserSchema — Defines the structure for user documents in MongoDB.
 *
 * Fields:
 * - email:          Unique identifier for authentication.
 * - password:       Stored as a bcrypt hash (never plain text).
 * - role:           Used by the RBAC policy engine (default: 'USER').
 * - refreshTokens:  Array of hashed refresh tokens for RTR tracking.
 */
export const UserSchema = new Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      default: 'USER',
    },
    refreshTokens: [
      {
        type: String,
      },
    ],
  },
  {
    timestamps: true, // Adds createdAt and updatedAt fields automatically
  }
);
