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
    emailVerified: {
      type: Boolean,
      default: false,
    },
    emailOtpHash: {
      type: String,
      default: null,
    },
    emailOtpExpiresAt: {
      type: Date,
      default: null,
    },
    otpVerifyAttempts: {
      type: Number,
      default: 0,
    },
    otpLockedUntil: {
      type: Date,
      default: null,
    },
    otpResendAvailableAt: {
      type: Date,
      default: null,
    },
    role: {
      type: String,
      default: 'USER',
    },
    permissions: [
      {
        type: String,
      },
    ],
    failedLoginAttempts: {
      type: Number,
      default: 0,
    },
    lockUntil: {
      type: Date,
      default: null,
    },
    refreshSessions: [
      {
        hashedToken: {
          type: String,
          required: true,
        },
        userAgent: {
          type: String,
        },
        ip: {
          type: String,
        },
        createdAt: {
          type: Date,
          default: Date.now,
        },
        lastUsedAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
  },
  {
    timestamps: true, // Adds createdAt and updatedAt fields automatically
  }
);

/**
 * RoleSchema — Defines dynamic role records that admins can manage.
 *
 * Fields:
 * - name:        Unique role name (normalized to uppercase).
 * - permissions: Optional role-level permissions.
 */
export const RoleSchema = new Schema(
  {
    name: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      uppercase: true,
    },
    permissions: [
      {
        type: String,
      },
    ],
  },
  {
    timestamps: true,
  }
);

/**
 * AuditLogSchema — Stores auth/admin security events for observability.
 */
export const AuditLogSchema = new Schema(
  {
    actorUserId: {
      type: String,
      default: null,
    },
    actorEmail: {
      type: String,
      default: null,
    },
    targetUserId: {
      type: String,
      default: null,
    },
    targetEmail: {
      type: String,
      default: null,
    },
    action: {
      type: String,
      required: true,
      index: true,
    },
    status: {
      type: String,
      enum: ['SUCCESS', 'FAILURE'],
      required: true,
      index: true,
    },
    ip: {
      type: String,
      default: null,
    },
    userAgent: {
      type: String,
      default: null,
    },
    details: {
      type: Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
  }
);
