// ============================================================
// AuthCore — Example / Demo Express Server
// ============================================================
// This is a standalone Express application that demonstrates
// how to consume the AuthCore library with MongoDB/Mongoose.
//
// Uses a configurable MongoDB URI (local MongoDB/Compass friendly).
//
// Endpoints:
//   POST   /api/auth/register   — Create a new user
//   POST   /api/auth/login      — Authenticate and receive tokens
//   POST   /api/auth/refresh    — Rotate refresh token
//   POST   /api/auth/logout     — Revoke tokens and clear cookie
//   GET    /api/protected       — Requires any authenticated user
//   GET    /api/admin           — Requires ADMIN role only
// ============================================================

import express from 'express';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import nodemailer from 'nodemailer';
import { randomInt } from 'crypto';
import 'dotenv/config';

// Import everything from the authcore library source
import {
  AuthService,
  MongoAuthAdapter,
  UserSchema,
  RoleSchema,
  AuditLogSchema,
  CryptoService,
  requireAuth,
  requireRole,
  requirePermissions,
  catchAsync,
  globalErrorHandler,
  AppError,
} from '../src/index';

// -----------------------------------------------------------
// Configuration
// -----------------------------------------------------------

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/authcore';
const ACCESS_TOKEN_SECRET = process.env.ACCESS_SECRET || 'access-secret-key-change-in-production';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_SECRET || 'refresh-secret-key-change-in-production';
const OTP_TTL_MS = Number(process.env.OTP_TTL_MS || 10 * 60 * 1000);
const OTP_MAX_VERIFY_ATTEMPTS = Number(process.env.OTP_MAX_VERIFY_ATTEMPTS || 5);
const OTP_VERIFY_LOCK_MS = Number(process.env.OTP_VERIFY_LOCK_MS || 10 * 60 * 1000);
const OTP_RESEND_COOLDOWN_MS = Number(process.env.OTP_RESEND_COOLDOWN_MS || 60 * 1000);

function maskMongoUri(uri: string): string {
  return uri.replace(/(mongodb(?:\+srv)?:\/\/)([^@]+)@/, '$1***:***@');
}

const smtpTransporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'localhost',
  port: Number(process.env.SMTP_PORT || 1025),
  secure: (process.env.SMTP_SECURE || 'false') === 'true',
  auth:
    process.env.SMTP_USER && process.env.SMTP_PASS
      ? {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
        }
      : undefined,
});

function generateOtp(): string {
  return randomInt(100000, 1000000).toString();
}

async function issueAndSendOtp(email: string): Promise<void> {
  const hasSmtpAuth = Boolean(process.env.SMTP_USER && process.env.SMTP_PASS);
  const looksLikePlaceholder =
    (process.env.SMTP_USER || '').includes('your_email@gmail.com') ||
    (process.env.SMTP_PASS || '').includes('your_gmail_app_password');

  if (!hasSmtpAuth || looksLikePlaceholder) {
    throw new AppError(
      500,
      'SMTP is not configured. Set SMTP_USER/SMTP_PASS in .env with real values.'
    );
  }

  const otp = generateOtp();
  const otpHash = await cryptoService.hashData(otp);
  const expiresAt = new Date(Date.now() + OTP_TTL_MS);
  const resendAvailableAt = new Date(Date.now() + OTP_RESEND_COOLDOWN_MS);

  await UserModel.findOneAndUpdate(
    { email },
    {
      $set: {
        emailOtpHash: otpHash,
        emailOtpExpiresAt: expiresAt,
        otpVerifyAttempts: 0,
        otpLockedUntil: null,
        otpResendAvailableAt: resendAvailableAt,
      },
    }
  );

  try {
    await smtpTransporter.sendMail({
      from: process.env.OTP_FROM_EMAIL || 'no-reply@authcore.local',
      to: email,
      subject: 'Your AuthCore verification OTP',
      text: `Your OTP is ${otp}. It expires in ${Math.floor(OTP_TTL_MS / 60000)} minutes.`,
      html: `<p>Your OTP is <strong>${otp}</strong>.</p><p>It expires in ${Math.floor(
        OTP_TTL_MS / 60000
      )} minutes.</p>`,
    });
  } catch (error: any) {
    const code = error?.code ? ` (${error.code})` : '';
    console.error('SMTP sendMail failed:', error?.message || error);
    throw new AppError(
      500,
      `OTP email delivery failed${code}. Check SMTP settings, Gmail app password, and sender address.`
    );
  }
}

// -----------------------------------------------------------
// MongoDB Connection & Model Setup
// -----------------------------------------------------------

// Compile the model using the schema exported by AuthCore
const UserModel = mongoose.model('User', UserSchema);
const RoleModel = mongoose.model('Role', RoleSchema);
const AuditLogModel = mongoose.model('AuditLog', AuditLogSchema);

type AuditLogPayload = {
  actorUserId?: string | null;
  actorEmail?: string | null;
  targetUserId?: string | null;
  targetEmail?: string | null;
  action: string;
  status: 'SUCCESS' | 'FAILURE';
  ip?: string | null;
  userAgent?: string | null;
  details?: Record<string, unknown>;
};

async function logEvent(payload: AuditLogPayload): Promise<void> {
  try {
    await AuditLogModel.create({
      actorUserId: payload.actorUserId || null,
      actorEmail: payload.actorEmail || null,
      targetUserId: payload.targetUserId || null,
      targetEmail: payload.targetEmail || null,
      action: payload.action,
      status: payload.status,
      ip: payload.ip || null,
      userAgent: payload.userAgent || null,
      details: payload.details || {},
    });
  } catch (error) {
    // Logging should never break auth flow.
    console.error('Audit log write failed:', (error as Error).message);
  }
}

function toAdminUserView(user: any) {
  return {
    id: String(user._id),
    email: user.email,
    role: user.role,
    permissions: user.permissions || [],
    emailVerified: user.emailVerified,
    failedLoginAttempts: user.failedLoginAttempts || 0,
    lockUntil: user.lockUntil || null,
    otpVerifyAttempts: user.otpVerifyAttempts || 0,
    otpLockedUntil: user.otpLockedUntil || null,
    otpResendAvailableAt: user.otpResendAvailableAt || null,
    refreshSessions: (user.refreshSessions || []).map((s: any) => ({
      id: String(s._id),
      userAgent: s.userAgent || null,
      ip: s.ip || null,
      createdAt: s.createdAt || null,
      lastUsedAt: s.lastUsedAt || null,
    })),
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

async function ensureDefaultRoles(): Promise<void> {
  await RoleModel.updateOne(
    { name: 'USER' },
    { $setOnInsert: { name: 'USER', permissions: [] } },
    { upsert: true }
  );

  await RoleModel.updateOne(
    { name: 'ADMIN' },
    { $setOnInsert: { name: 'ADMIN', permissions: ['USERS_MANAGE', 'ROLES_MANAGE'] } },
    { upsert: true }
  );
}

async function assertRoleExists(role: string): Promise<void> {
  const normalizedRole = role.trim().toUpperCase();
  const exists = await RoleModel.exists({ name: normalizedRole });
  if (!exists) {
    throw new AppError(400, `Role ${normalizedRole} does not exist. Create it from admin role management first.`);
  }
}

// Create the adapter and service instances
const adapter = new MongoAuthAdapter(UserModel);
const cryptoService = new CryptoService({
  accessTokenSecret: ACCESS_TOKEN_SECRET,
  refreshTokenSecret: REFRESH_TOKEN_SECRET,
});
const authService = new AuthService(adapter, {
  accessTokenSecret: ACCESS_TOKEN_SECRET,
  refreshTokenSecret: REFRESH_TOKEN_SECRET,
  secureCookies: false, // Set to true in production with HTTPS
});

// -----------------------------------------------------------
// Express App Setup
// -----------------------------------------------------------

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(express.static('example/public'));

// -----------------------------------------------------------
// AUTH ROUTES
// -----------------------------------------------------------

/**
 * POST /api/auth/register
 * Creates a new user with a hashed password.
 */
app.post(
  '/api/auth/register',
  catchAsync(async (req: express.Request, res: express.Response) => {
    const { email, password, role, permissions } = req.body;

    if (!email || !password) {
      throw new AppError(400, 'Email and password are required.');
    }

    // Check if user already exists
    const existingUser = await adapter.getUserByEmail(email);
    if (existingUser) {
      throw new AppError(409, 'A user with this email already exists.');
    }

    const normalizedRole = (role || 'USER').trim().toUpperCase();
    await assertRoleExists(normalizedRole);

    // Hash the password before saving
    const hashedPassword = await cryptoService.hashData(password);

    // Create the user in MongoDB
    const newUser = await UserModel.create({
      email,
      password: hashedPassword,
      emailVerified: false,
      role: normalizedRole,
      permissions: Array.isArray(permissions) ? permissions : [],
    });

    await issueAndSendOtp(email);

    await logEvent({
      action: 'AUTH_REGISTER',
      status: 'SUCCESS',
      targetUserId: String(newUser._id),
      targetEmail: newUser.email,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      details: { role: normalizedRole },
    });

    res.status(201).json({
      status: 'success',
      message: 'User registered. OTP sent to email for verification.',
      user: {
        id: newUser._id,
        email: newUser.email,
        role: newUser.role,
        permissions: newUser.permissions,
        emailVerified: false,
      },
    });
  })
);

/**
 * POST /api/auth/verify-otp
 * Verifies email OTP and marks account as verified.
 */
app.post(
  '/api/auth/verify-otp',
  catchAsync(async (req: express.Request, res: express.Response) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
      throw new AppError(400, 'Email and OTP are required.');
    }

    const user = await UserModel.findOne({ email }).lean();
    if (!user) {
      await logEvent({
        action: 'AUTH_VERIFY_OTP',
        status: 'FAILURE',
        targetEmail: email,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        details: { reason: 'USER_NOT_FOUND' },
      });
      throw new AppError(404, 'User not found.');
    }

    if ((user as any).emailVerified) {
      res.status(200).json({
        status: 'success',
        message: 'Email is already verified.',
      });
      return;
    }

    if ((user as any).otpLockedUntil && new Date((user as any).otpLockedUntil).getTime() > Date.now()) {
      await logEvent({
        action: 'AUTH_VERIFY_OTP',
        status: 'FAILURE',
        targetUserId: String((user as any)._id),
        targetEmail: String((user as any).email),
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        details: { reason: 'OTP_LOCKED' },
      });
      throw new AppError(429, 'OTP verification temporarily locked due to too many failed attempts.');
    }

    if (!(user as any).emailOtpHash || !(user as any).emailOtpExpiresAt) {
      await logEvent({
        action: 'AUTH_VERIFY_OTP',
        status: 'FAILURE',
        targetUserId: String((user as any)._id),
        targetEmail: String((user as any).email),
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        details: { reason: 'NO_OTP' },
      });
      throw new AppError(400, 'No OTP available. Please request a new OTP.');
    }

    if (new Date((user as any).emailOtpExpiresAt).getTime() < Date.now()) {
      await logEvent({
        action: 'AUTH_VERIFY_OTP',
        status: 'FAILURE',
        targetUserId: String((user as any)._id),
        targetEmail: String((user as any).email),
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        details: { reason: 'OTP_EXPIRED' },
      });
      throw new AppError(400, 'OTP expired. Please request a new OTP.');
    }

    const isMatch = await cryptoService.compareData(otp, (user as any).emailOtpHash);
    if (!isMatch) {
      const attempts = ((user as any).otpVerifyAttempts || 0) + 1;
      const lockUntil =
        attempts >= OTP_MAX_VERIFY_ATTEMPTS
          ? new Date(Date.now() + OTP_VERIFY_LOCK_MS)
          : null;

      await UserModel.findOneAndUpdate(
        { email },
        {
          $set: {
            otpVerifyAttempts: attempts,
            otpLockedUntil: lockUntil,
          },
        }
      );

      await logEvent({
        action: 'AUTH_VERIFY_OTP',
        status: 'FAILURE',
        targetUserId: String((user as any)._id),
        targetEmail: String((user as any).email),
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        details: { reason: lockUntil ? 'OTP_LOCKED_AFTER_FAILURES' : 'INVALID_OTP' },
      });

      if (lockUntil) {
        throw new AppError(429, 'OTP verification temporarily locked due to too many failed attempts.');
      }

      throw new AppError(400, 'Invalid OTP.');
    }

    await UserModel.findOneAndUpdate(
      { email },
      {
        $set: {
          emailVerified: true,
          emailOtpHash: null,
          emailOtpExpiresAt: null,
          otpVerifyAttempts: 0,
          otpLockedUntil: null,
          otpResendAvailableAt: null,
        },
      }
    );

    await logEvent({
      action: 'AUTH_VERIFY_OTP',
      status: 'SUCCESS',
      targetUserId: String((user as any)._id),
      targetEmail: String((user as any).email),
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.status(200).json({
      status: 'success',
      message: 'Email verified successfully.',
    });
  })
);

/**
 * POST /api/auth/resend-otp
 * Generates a new random OTP and sends it over SMTP.
 */
app.post(
  '/api/auth/resend-otp',
  catchAsync(async (req: express.Request, res: express.Response) => {
    const { email } = req.body;

    if (!email) {
      throw new AppError(400, 'Email is required.');
    }

    const user = await UserModel.findOne({ email }).lean();
    if (!user) {
      await logEvent({
        action: 'AUTH_RESEND_OTP',
        status: 'FAILURE',
        targetEmail: email,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        details: { reason: 'USER_NOT_FOUND' },
      });
      throw new AppError(404, 'User not found.');
    }

    if ((user as any).emailVerified) {
      res.status(200).json({
        status: 'success',
        message: 'Email is already verified.',
      });
      return;
    }

    if (
      (user as any).otpResendAvailableAt &&
      new Date((user as any).otpResendAvailableAt).getTime() > Date.now()
    ) {
      const waitMs = new Date((user as any).otpResendAvailableAt).getTime() - Date.now();
      const waitSec = Math.ceil(waitMs / 1000);
      throw new AppError(429, `Please wait ${waitSec}s before requesting a new OTP.`);
    }

    await issueAndSendOtp(email);

    await logEvent({
      action: 'AUTH_RESEND_OTP',
      status: 'SUCCESS',
      targetUserId: String((user as any)._id),
      targetEmail: String((user as any).email),
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.status(200).json({
      status: 'success',
      message: 'A new OTP has been sent to your email.',
    });
  })
);

/**
 * POST /api/auth/login
 * Authenticates user and returns access token + sets refresh cookie.
 */
app.post(
  '/api/auth/login',
  catchAsync(async (req: express.Request, res: express.Response) => {
    const { email, password } = req.body;

    if (!email || !password) {
      throw new AppError(400, 'Email and password are required.');
    }

    let result;
    try {
      result = await authService.login(email, password, req, res);
    } catch (error) {
      await logEvent({
        action: 'AUTH_LOGIN',
        status: 'FAILURE',
        targetEmail: email,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        details: { reason: (error as Error).message },
      });
      throw error;
    }

    await logEvent({
      action: 'AUTH_LOGIN',
      status: 'SUCCESS',
      actorUserId: result.user.id,
      actorEmail: result.user.email,
      targetUserId: result.user.id,
      targetEmail: result.user.email,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.status(200).json({
      status: 'success',
      message: 'Login successful.',
      accessToken: result.accessToken,
      user: result.user,
    });
  })
);

/**
 * GET /api/auth/sessions
 * Lists all active refresh-token-backed sessions for the logged in user.
 */
app.get(
  '/api/auth/sessions',
  requireAuth(ACCESS_TOKEN_SECRET),
  catchAsync(async (req: express.Request, res: express.Response) => {
    const sessions = await authService.listSessions(req.user!.id);
    res.status(200).json({
      status: 'success',
      sessions,
    });
  })
);

/**
 * DELETE /api/auth/sessions/:sessionId
 * Revokes one active session.
 */
app.delete(
  '/api/auth/sessions/:sessionId',
  requireAuth(ACCESS_TOKEN_SECRET),
  catchAsync(async (req: express.Request, res: express.Response) => {
    const result = await authService.revokeSession(req.user!.id, req.params.sessionId);
    res.status(200).json({
      status: 'success',
      message: result.message,
    });
  })
);

/**
 * POST /api/auth/refresh
 * Uses Refresh Token Rotation (RTR) to issue a new token pair.
 */
app.post(
  '/api/auth/refresh',
  catchAsync(async (req: express.Request, res: express.Response) => {
    const result = await authService.refreshToken(req, res);

    res.status(200).json({
      status: 'success',
      message: 'Token refreshed successfully.',
      accessToken: result.accessToken,
    });
  })
);

/**
 * POST /api/auth/logout
 * Revokes all refresh tokens and clears the cookie.
 */
app.post(
  '/api/auth/logout',
  catchAsync(async (req: express.Request, res: express.Response) => {
    const actorId = req.user?.id || null;
    const actorEmail = req.user?.email || null;
    const result = await authService.logout(req, res);

    await logEvent({
      action: 'AUTH_LOGOUT',
      status: 'SUCCESS',
      actorUserId: actorId,
      actorEmail,
      targetUserId: actorId,
      targetEmail: actorEmail,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.status(200).json({
      status: 'success',
      message: result.message,
    });
  })
);

// -----------------------------------------------------------
// PROTECTED ROUTES (Demonstrates middleware usage)
// -----------------------------------------------------------

/**
 * GET /api/protected
 * Accessible by any authenticated user (any role).
 */
app.get(
  '/api/protected',
  requireAuth(ACCESS_TOKEN_SECRET),
  catchAsync(async (req: express.Request, res: express.Response) => {
    res.status(200).json({
      status: 'success',
      message: `Hello ${req.user!.email}, you are authenticated.`,
      user: req.user,
    });
  })
);

/**
 * GET /api/admin
 * Accessible ONLY by users with the ADMIN role.
 * Demonstrates the centralized RBAC policy engine.
 */
app.get(
  '/api/admin',
  requireAuth(ACCESS_TOKEN_SECRET),
  requireRole(['ADMIN']),
  catchAsync(async (req: express.Request, res: express.Response) => {
    res.status(200).json({
      status: 'success',
      message: `Welcome Admin ${req.user!.email}. You have elevated privileges.`,
      user: req.user,
    });
  })
);

/**
 * GET /api/admin/users
 * Admin route to list users.
 */
app.get(
  '/api/admin/users',
  requireAuth(ACCESS_TOKEN_SECRET),
  requireRole(['ADMIN']),
  catchAsync(async (req: express.Request, res: express.Response) => {
    const users = await UserModel.find({}, {
      email: 1,
      role: 1,
      permissions: 1,
      emailVerified: 1,
      failedLoginAttempts: 1,
      lockUntil: 1,
      otpVerifyAttempts: 1,
      otpLockedUntil: 1,
      otpResendAvailableAt: 1,
      refreshSessions: 1,
      createdAt: 1,
      updatedAt: 1,
    }).lean();
    res.status(200).json({
      status: 'success',
      users: users.map(toAdminUserView),
    });
  })
);

/**
 * GET /api/admin/users/:userId
 * Admin route to view all safe details for one user.
 */
app.get(
  '/api/admin/users/:userId',
  requireAuth(ACCESS_TOKEN_SECRET),
  requireRole(['ADMIN']),
  catchAsync(async (req: express.Request, res: express.Response) => {
    if (!mongoose.Types.ObjectId.isValid(req.params.userId)) {
      throw new AppError(400, 'Invalid user id format.');
    }

    const user = await UserModel.findById(req.params.userId, {
      email: 1,
      role: 1,
      permissions: 1,
      emailVerified: 1,
      failedLoginAttempts: 1,
      lockUntil: 1,
      otpVerifyAttempts: 1,
      otpLockedUntil: 1,
      otpResendAvailableAt: 1,
      refreshSessions: 1,
      createdAt: 1,
      updatedAt: 1,
    }).lean();

    if (!user) {
      throw new AppError(404, 'User not found.');
    }

    res.status(200).json({
      status: 'success',
      user: toAdminUserView(user),
    });
  })
);

/**
 * PATCH /api/admin/users/:userId
 * Admin route to update role and permissions.
 */
app.patch(
  '/api/admin/users/:userId',
  requireAuth(ACCESS_TOKEN_SECRET),
  requireRole(['ADMIN']),
  catchAsync(async (req: express.Request, res: express.Response) => {
    if (!mongoose.Types.ObjectId.isValid(req.params.userId)) {
      throw new AppError(400, 'Invalid user id format.');
    }

    const { role, permissions } = req.body;
    const updates: Record<string, unknown> = {};

    if (role) {
      const normalizedRole = String(role).trim().toUpperCase();
      await assertRoleExists(normalizedRole);
      updates.role = normalizedRole;
    }
    if (Array.isArray(permissions)) updates.permissions = permissions;

    if (Object.keys(updates).length === 0) {
      throw new AppError(400, 'Provide role and/or permissions to update.');
    }

    const updatedUser = await UserModel.findByIdAndUpdate(req.params.userId, updates, {
      new: true,
      fields: { email: 1, role: 1, permissions: 1 },
    }).lean();

    if (!updatedUser) {
      throw new AppError(404, 'User not found.');
    }

    res.status(200).json({
      status: 'success',
      user: updatedUser,
    });

    await logEvent({
      action: 'ADMIN_USER_UPDATE',
      status: 'SUCCESS',
      actorUserId: req.user?.id || null,
      actorEmail: req.user?.email || null,
      targetUserId: req.params.userId,
      targetEmail: (updatedUser as any).email,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      details: {
        updatedRole: (updates.role as string | undefined) || null,
        updatedPermissions: (updates.permissions as string[] | undefined) || null,
      },
    });
  })
);

/**
 * GET /api/admin/roles
 * Admin route to list available roles.
 */
app.get(
  '/api/admin/roles',
  requireAuth(ACCESS_TOKEN_SECRET),
  requireRole(['ADMIN']),
  catchAsync(async (req: express.Request, res: express.Response) => {
    const roles = await RoleModel.find({}, { name: 1, permissions: 1 }).sort({ name: 1 }).lean();
    res.status(200).json({
      status: 'success',
      roles,
    });
  })
);

/**
 * POST /api/admin/roles
 * Admin route to create a new role.
 */
app.post(
  '/api/admin/roles',
  requireAuth(ACCESS_TOKEN_SECRET),
  requireRole(['ADMIN']),
  catchAsync(async (req: express.Request, res: express.Response) => {
    const { name, permissions } = req.body;

    if (!name || typeof name !== 'string') {
      throw new AppError(400, 'Role name is required.');
    }

    const normalizedName = name.trim().toUpperCase();
    const existing = await RoleModel.findOne({ name: normalizedName }).lean();
    if (existing) {
      throw new AppError(409, `Role ${normalizedName} already exists.`);
    }

    const role = await RoleModel.create({
      name: normalizedName,
      permissions: Array.isArray(permissions) ? permissions : [],
    });

    res.status(201).json({
      status: 'success',
      role: {
        id: role._id,
        name: role.name,
        permissions: role.permissions,
      },
    });

    await logEvent({
      action: 'ADMIN_ROLE_CREATE',
      status: 'SUCCESS',
      actorUserId: req.user?.id || null,
      actorEmail: req.user?.email || null,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      details: {
        roleName: role.name,
        permissions: role.permissions,
      },
    });
  })
);


/**
 * GET /api/reports/finance
 * Example permission-protected route.
 */
app.get(
  '/api/reports/finance',
  requireAuth(ACCESS_TOKEN_SECRET),
  requirePermissions(['REPORTS_READ']),
  catchAsync(async (req: express.Request, res: express.Response) => {
    res.status(200).json({
      status: 'success',
      message: 'Finance report access granted.',
      user: req.user,
    });
  })
);

// -----------------------------------------------------------
// Global Error Handler (must be last middleware)
// -----------------------------------------------------------

app.use(globalErrorHandler);

// -----------------------------------------------------------
// Start Server
// -----------------------------------------------------------

async function main() {
  await mongoose.connect(MONGODB_URI);
  console.log('✅ Connected to MongoDB:', maskMongoUri(MONGODB_URI));

  await ensureDefaultRoles();
  console.log('✅ Default roles ensured: USER, ADMIN');

  console.log('📧 SMTP config:', {
    host: process.env.SMTP_HOST || 'localhost',
    port: Number(process.env.SMTP_PORT || 1025),
    secure: (process.env.SMTP_SECURE || 'false') === 'true',
    hasAuth: Boolean(process.env.SMTP_USER && process.env.SMTP_PASS),
    from: process.env.OTP_FROM_EMAIL || 'no-reply@authcore.local',
  });

  try {
    await smtpTransporter.verify();
    console.log('✅ SMTP connection verified.');
  } catch (error: any) {
    console.error('⚠️ SMTP verify failed:', error?.message || error);
  }

  app.listen(PORT, () => {
    console.log(`🚀 AuthCore Demo Server running on http://localhost:${PORT}`);
    console.log('🖥️  Interface: http://localhost:' + PORT);
    console.log('');
    console.log('Available endpoints:');
    console.log('  POST   /api/auth/register   — Register a new user');
    console.log('  POST   /api/auth/verify-otp — Verify email with OTP');
    console.log('  POST   /api/auth/resend-otp — Resend verification OTP');
    console.log('  POST   /api/auth/login      — Login and get tokens');
    console.log('  POST   /api/auth/refresh    — Refresh access token');
    console.log('  POST   /api/auth/logout     — Logout and revoke tokens');
    console.log('  GET    /api/protected       — Protected route (any role)');
    console.log('  GET    /api/admin           — Admin-only route');
    console.log('  GET    /api/admin/users     — List all user details (admin)');
    console.log('  GET    /api/admin/users/:userId — View one user details (admin)');
    console.log('  GET    /api/admin/roles     — List available roles (admin)');
    console.log('  POST   /api/admin/roles     — Create a new role (admin)');
    console.log('');
    console.log('OTP security config:');
    console.log('  OTP_TTL_MS               =', OTP_TTL_MS);
    console.log('  OTP_MAX_VERIFY_ATTEMPTS  =', OTP_MAX_VERIFY_ATTEMPTS);
    console.log('  OTP_VERIFY_LOCK_MS       =', OTP_VERIFY_LOCK_MS);
    console.log('  OTP_RESEND_COOLDOWN_MS   =', OTP_RESEND_COOLDOWN_MS);
  });
}

main().catch((err) => {
  console.error('❌ Startup failed:', err.message);
  process.exit(1);
});
