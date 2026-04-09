# AuthCore

**AuthCore** is a reusable, production-ready authentication and RBAC library for Express and Node.js.

Build auth once. Reuse everywhere. Swap databases anytime.

## Key Features

- **JWT Token Flow** — Access tokens (short-lived) + refresh tokens (long-lived) with automatic rotation
- **Refresh Token Rotation** — Detects token reuse and revokes compromised sessions
- **Login Lockout** — Brute-force protection with configurable attempt limits and lockout duration
- **Role-Based Access Control (RBAC)** — Coarse-grained roles (ADMIN, USER) + fine-grained permissions
- **Multi-Device Sessions** — Track and revoke sessions per device with IP/user-agent metadata
- **Email OTP Verification** — Built-in email verification via SMTP integration
- **Audit Logging** — Track all authentication events and admin actions
- **Adapter Pattern** — Plug in MongoDB, PostgreSQL, MySQL, or any database without changing auth logic
- **TypeScript First** — Full type safety and IDE support
- **Error Handling** — Global error handler with consistent JSON responses
- **Middleware Stack** — `requireAuth`, `requireRole`, `requirePermissions` out of the box

## Why AuthCore?

| Feature | AuthCore | Firebase/Auth0 | Passport.js | NextAuth.js |
|---------|----------|---|---|---|
| No Vendor Lock-in | ✅ | ❌ | ✅ | ❌ (Next.js only) |
| Database Agnostic | ✅ | ❌ | ❌ | ❌ |
| Self-Hostable | ✅ | ❌ | ✅ | ✅ |
| Complete Flows | ✅ | ✅ | ❌ (only middleware) | ✅ |
| Refresh Rotation | ✅ | ✅ | ❌ | ✅ |
| Multi-Device Sessions | ✅ | ✅ | ❌ | ❌ |
| Built-in RBAC | ✅ | ✅ | ❌ | ❌ |
| No Monthly Cost | ✅ | ❌ | ✅ | ✅ |

## Architecture

AuthCore follows the **Adapter Pattern** to decouple authentication logic from database implementation:

```
┌─────────────────────────────┐
│  Your Express Application   │
└──────────────┬──────────────┘
               │
               ↓
    ┌──────────────────────┐
    │   AuthService        │  ← Orchestrates all auth flows
    │   (DB-Agnostic)      │
    └────────┬─────────────┘
             │
    ┌────────┴──────────────┐
    ↓                       ↓
┌─────────────┐      ┌──────────────────┐
│ CryptoService       │ AuthDatabaseAdapter (Interface)
│ - JWT signing       ├─────────────────────────┐
│ - Bcrypt hashing    │                         │
│ - Token validation  │                         │
└─────────────┘       ├─────────────────────────┤
              ↓                       ↓
           ┌──────────────────┐  ┌─────────────────────┐
           │ MongoAuthAdapter │  │ PostgresAuthAdapter │
           │ (MongoDB impl)   │  │ (PostgreSQL impl)   │
           └──────────────────┘  └─────────────────────┘
```

This means:
- Core auth logic is **database-agnostic**
- You can swap MongoDB for PostgreSQL/MySQL without touching `AuthService`
- Easy to test with mock adapters
- Easy to extend with custom databases

## Token & Session Flow

### Login Flow
```
User: POST /api/auth/login { email, password }
         ↓
  1. Query DB for user by email
  2. Verify password against bcrypt hash
  3. Generate accessToken (JWT, 15 min life)
  4. Generate refreshToken (JWT, 7 days life)
  5. Hash refreshToken and store in DB (session record)
  6. Set refreshToken in httpOnly cookie (XSS protection)
         ↓
Response: { accessToken, user: {id, email, role, permissions} }
```

### Protected Route Access
```
User: GET /api/protected
      Authorization: Bearer <accessToken>
         ↓
  1. requireAuth middleware validates JWT signature
  2. Extract user payload (id, role, email, permissions)
  3. Attach to req.user
  4. Call next()
         ↓
Route handler accesses req.user
```

### Token Refresh (Refresh Token Rotation)
```
User: POST /api/auth/refresh
      Cookie: refreshToken=<token>
         ↓
  1. Verify refreshToken JWT signature
  2. Find matching session in DB
     ├─ If found: Rotate out old token (delete it)
     └─ If NOT found: ALERT! Revoke all sessions (theft detected)
  3. Issue new accessToken + refreshToken pair
  4. Hash and store new token
  5. Set new cookie
         ↓
Response: { accessToken, user }

⚠️  If attacker steals old refresh token and tries to reuse it,
the system will detect the reuse and revoke all sessions.
```

### Login Lockout (Brute-Force Protection)
```
User: Failed login attempt 5 times (within 15 min)
         ↓
  1. On each failed attempt: failedLoginAttempts++
  2. When failedLoginAttempts >= maxAttempts (default 5)
  3. Set lockUntil = now + 15 minutes
         ↓
  4. Next login attempt: Check if locked
     ├─ If locked: Return 429 "Too Many Attempts"
     └─ If unlocked: Allow login, reset counter
```

## Install

## Install

```bash
npm install authcore express mongoose cookie-parser jsonwebtoken bcrypt
```

For TypeScript projects:

```bash
npm install -D typescript @types/express @types/cookie-parser @types/node
```

**Note:** Current version ships with MongoDB adapter. For PostgreSQL/MySQL, you'll need to implement your own adapter or wait for community updates.

## 5-Minute Quick Start

1. Create env variables:

```env
MONGODB_URI=mongodb://127.0.0.1:27017/myapp
ACCESS_SECRET=replace-with-strong-access-secret
REFRESH_SECRET=replace-with-strong-refresh-secret
PORT=3000
```

2. Create your server:

```ts
import express from 'express';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';

import {
  AuthService,
  MongoAuthAdapter,
  UserSchema,
  CryptoService,
  requireAuth,
  requireRole,
  requirePermissions,
  catchAsync,
  globalErrorHandler,
  AppError,
} from 'authcore';

const app = express();
app.use(express.json());
app.use(cookieParser());

const UserModel = mongoose.model('User', UserSchema);

const adapter = new MongoAuthAdapter(UserModel);
const cryptoService = new CryptoService({
  accessTokenSecret: process.env.ACCESS_SECRET!,
  refreshTokenSecret: process.env.REFRESH_SECRET!,
});
const authService = new AuthService(adapter, {
  accessTokenSecret: process.env.ACCESS_SECRET!,
  refreshTokenSecret: process.env.REFRESH_SECRET!,
  secureCookies: false,
});

app.post(
  '/api/auth/register',
  catchAsync(async (req, res) => {
    const { email, password, role = 'USER' } = req.body;
    if (!email || !password) throw new AppError(400, 'Email and password are required.');

    const existing = await adapter.getUserByEmail(email);
    if (existing) throw new AppError(409, 'User already exists.');

    const hashedPassword = await cryptoService.hashData(password);
    const user = await UserModel.create({ email, password: hashedPassword, role });

    res.status(201).json({
      status: 'success',
      user: { id: user._id, email: user.email, role: user.role },
    });
  })
);

app.post(
  '/api/auth/login',
  catchAsync(async (req, res) => {
    const { email, password } = req.body;
    const { user, accessToken, refreshToken } = await authService.loginUser(email, password);

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({ status: 'success', accessToken, user });
  })
);

app.post(
  '/api/auth/refresh',
  catchAsync(async (req, res) => {
    const refreshToken = req.cookies?.refreshToken;
    if (!refreshToken) throw new AppError(401, 'Refresh token missing.');

    const result = await authService.refreshToken(refreshToken);
    res.cookie('refreshToken', result.refreshToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({ status: 'success', accessToken: result.accessToken });
  })
);

app.get('/api/protected', requireAuth, (req, res) => {
  res.json({ status: 'success', user: req.user });
});

app.get('/api/admin', requireAuth, requireRole('ADMIN'), (_req, res) => {
  res.json({ status: 'success', message: 'Admin route access granted.' });
});

app.get('/api/reports', requireAuth, requirePermissions(['REPORTS_READ']), (_req, res) => {
  res.json({ status: 'success', message: 'Reports route access granted.' });
});

app.use(globalErrorHandler);

async function start() {
  await mongoose.connect(process.env.MONGODB_URI!);
  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
}

start().catch((error) => {
  console.error('Server startup failed:', error);
  process.exit(1);
});
```

3. Run:

```bash
npm run dev
```

## Quick Routes You Usually Need

- POST /api/auth/register
- POST /api/auth/login
- POST /api/auth/refresh
- POST /api/auth/logout
- GET /api/protected (requireAuth)
- GET /api/admin (requireAuth + requireRole)
- GET /api/reports (requireAuth + requirePermissions)

## API Surface

Main exports:
- AuthService
- MongoAuthAdapter
- UserSchema
- RoleSchema
- AuditLogSchema
- CryptoService
- requireAuth
- requireRole
- requirePermissions
- AppError
- catchAsync
- globalErrorHandler

## Local Development

To work on the library itself:

```bash
npm install
npm run build      # Build dist/
npm run test       # Run Vitest
npm run dev        # Start example server on http://localhost:3000
npm run lint       # Check code quality
```

The example server demonstrates:
- User registration and login
- Protected routes (requireAuth)
- Admin routes (requireRole)
- Permission-based routes (requirePermissions)
- Multi-user session management
- OTP email verification (if SMTP configured)

Open browser to `http://localhost:3000` to test the interactive dashboard.

## Testing

```bash
npm run test       # Run all tests
npm run test:watch # Watch mode
```

Tests cover:
- Token generation and validation
- Failed token scenarios (tampered, expired, invalid)
- Middleware authorization flows
- Error handling
- Adapter mock implementations

## Publishing

```bash
npm login                          # Auth with npm
npm run test                       # Ensure tests pass
npm run build                      # Build dist/
npm publish --access public        # Publish to npm
```

This package includes:
- `prepare` script: Auto-builds on `npm install` from git
- `prepublishOnly`: Prevents publishing without tests + build

## Security Best Practices

When deploying to production:

1. **Secrets Management**
   ```env
   # Use strong, random secrets (min 32 characters)
   ACCESS_SECRET=<strong-random-string>
   REFRESH_SECRET=<different-strong-random>
   ```
   Never commit secrets. Use environment variables or secret managers.

2. **HTTPS Only**
   ```ts
   const authService = new AuthService(adapter, {
     secureCookies: true,  // Enable in production
     // ... other config
   });
   ```

3. **CORS Configuration**
   ```ts
   import cors from 'cors';
   app.use(cors({
     origin: process.env.FRONTEND_URL,
     credentials: true,
   }));
   ```

4. **Rate Limiting**
   ```ts
   import rateLimit from 'express-rate-limit';
   const limiter = rateLimit({
     windowMs: 15 * 60 * 1000,
     max: 5,  // 5 login attempts per window
   });
   app.post('/api/auth/login', limiter, /* ... */);
   ```

5. **Logging & Monitoring**
   - Log all auth events (login, token refresh, failed attempts)
   - Monitor failed login spike (possible attack)
   - Alert on all-sessions-revoked events

## Troubleshooting

**Login fails with "Invalid token secret"**
- Ensure `ACCESS_SECRET` and `REFRESH_SECRET` are set and match across restarts
- Don't mix access and refresh secrets

**Mongo connection fails**
- Verify `MONGODB_URI` is correct
- Check network access (Atlas whitelist, firewall)
- Ensure MongoDB service is running

**Protected route returns 401**
- Send accessToken in header: `Authorization: Bearer <token>`
- Token may be expired (15 min default) — call `/api/auth/refresh`

**Refresh returns 401**
- Ensure `refreshToken` cookie is sent with credentials
- Browser may not send cookies cross-origin without `credentials: 'include'`
- Check cookie settings (`httpOnly`, `sameSite`, `secure`)

**All sessions revoked unexpectedly**
- Likely refresh token reuse detected (possible theft)
- User needs to login again
- Check audit logs for suspicious activity

## Extending with Custom Databases

AuthCore is database-agnostic thanks to the **Adapter Pattern**. To use PostgreSQL, MySQL, or any other database:

### 1. Implement the AuthDatabaseAdapter Interface

Create a new adapter file, e.g., `PostgresAuthAdapter.ts`:

```ts
import { AuthDatabaseAdapter, UserRecord, RefreshSessionRecord } from './DatabaseAdapter';

export class PostgresAuthAdapter implements AuthDatabaseAdapter {
  constructor(private pool: pg.Pool) {}

  async getUserByEmail(email: string): Promise<UserRecord | null> {
    const result = await this.pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (!result.rows.length) return null;
    
    const user = result.rows[0];
    return {
      id: user.id.toString(),
      role: user.role,
      email: user.email,
      password: user.password,
      emailVerified: user.email_verified,
      permissions: user.permissions || [],
      failedLoginAttempts: user.failed_login_attempts || 0,
      lockUntil: user.lock_until,
      refreshSessions: await this.getRefreshSessions(user.id),
    };
  }

  async saveRefreshToken(
    userId: string,
    hashedToken: string,
    metadata?: { userAgent?: string; ip?: string }
  ): Promise<string> {
    const sessionId = randomUUID();
    await this.pool.query(
      `INSERT INTO refresh_sessions (id, user_id, hashed_token, user_agent, ip, created_at, last_used_at)
       VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`,
      [sessionId, userId, hashedToken, metadata?.userAgent, metadata?.ip]
    );
    return sessionId;
  }

  async revokeRefreshToken(userId: string, hashedToken: string): Promise<void> {
    await this.pool.query(
      'DELETE FROM refresh_sessions WHERE user_id = $1 AND hashed_token = $2',
      [userId, hashedToken]
    );
  }

  async revokeRefreshSession(userId: string, sessionId: string): Promise<void> {
    await this.pool.query(
      'DELETE FROM refresh_sessions WHERE user_id = $1 AND id = $2',
      [userId, sessionId]
    );
  }

  async getRefreshSessions(userId: string): Promise<RefreshSessionRecord[]> {
    const result = await this.pool.query(
      'SELECT id, hashed_token, user_agent, ip, created_at, last_used_at FROM refresh_sessions WHERE user_id = $1',
      [userId]
    );
    return result.rows.map(row => ({
      id: row.id,
      hashedToken: row.hashed_token,
      userAgent: row.user_agent,
      ip: row.ip,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
    }));
  }

  async touchRefreshSession(userId: string, sessionId: string): Promise<void> {
    await this.pool.query(
      'UPDATE refresh_sessions SET last_used_at = NOW() WHERE user_id = $1 AND id = $2',
      [userId, sessionId]
    );
  }

  async revokeAllRefreshTokens(userId: string): Promise<void> {
    await this.pool.query('DELETE FROM refresh_sessions WHERE user_id = $1', [userId]);
  }

  async incrementFailedLoginAttempts(
    userId: string,
    maxAttempts: number,
    lockMs: number
  ): Promise<{ failedLoginAttempts: number; lockUntil: Date | null }> {
    const result = await this.pool.query(
      'UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1 RETURNING failed_login_attempts',
      [userId]
    );
    const attempts = result.rows[0].failed_login_attempts;
    
    if (attempts >= maxAttempts) {
      const lockUntil = new Date(Date.now() + lockMs);
      await this.pool.query(
        'UPDATE users SET lock_until = $1 WHERE id = $2',
        [lockUntil, userId]
      );
      return { failedLoginAttempts: attempts, lockUntil };
    }
    
    return { failedLoginAttempts: attempts, lockUntil: null };
  }

  async clearLoginFailures(userId: string): Promise<void> {
    await this.pool.query(
      'UPDATE users SET failed_login_attempts = 0, lock_until = NULL WHERE id = $1',
      [userId]
    );
  }
}
```

### 2. Create Database Schema

For PostgreSQL:

```sql
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(50) DEFAULT 'USER',
  permissions TEXT[] DEFAULT '{}',
  email_verified BOOLEAN DEFAULT false,
  failed_login_attempts INT DEFAULT 0,
  lock_until TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE refresh_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hashed_token VARCHAR(255) NOT NULL,
  user_agent TEXT,
  ip VARCHAR(45),
  created_at TIMESTAMP DEFAULT NOW(),
  last_used_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_sessions_user_id ON refresh_sessions(user_id);
```

### 3. Use Your Adapter

```ts
import pg from 'pg';
import { AuthService } from 'authcore';
import { PostgresAuthAdapter } from './PostgresAuthAdapter';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PostgresAuthAdapter(pool);

const authService = new AuthService(adapter, {
  accessTokenSecret: process.env.ACCESS_SECRET!,
  refreshTokenSecret: process.env.REFRESH_SECRET!,
  secureCookies: true,
});

// Use authService normally — adapter is completely swapped
```

## Features Deep Dive

### Role-Based Access Control (RBAC)

Two-level authorization:

```ts
// Level 1: Role-based (coarse-grained)
app.get('/admin', requireAuth, requireRole(['ADMIN']), (req, res) => {
  res.json({ message: 'Admin only' });
});

// Level 2: Permission-based (fine-grained)
app.get('/reports', requireAuth, requirePermissions(['REPORTS_READ']), (req, res) => {
  res.json({ message: 'Reports data' });
});
```

User payload includes both:
```ts
{
  id: 'user-123',
  email: 'admin@example.com',
  role: 'ADMIN',
  permissions: ['USERS_MANAGE', 'REPORTS_READ', 'AUDIT_VIEW']
}
```

### Multi-Device Sessions

Logout from one device or all devices:

```ts
// Get active sessions for user
const sessions = await authService.listSessions(userId);
// [ { id, userAgent, ip, createdAt, lastUsedAt }, ... ]

// Revoke one session
await authService.revokeSession(userId, sessionId);

// Logout (revoke only current session)
await authService.logout(req, res);

// Logout all devices (admin action)
await adapter.revokeAllRefreshTokens(userId);
```

### Email Verification (OTP)

See `example/server.ts` for full OTP flow. Requires SMTP:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
```

### Audit Logging

Track all authentication events:

```ts
await AuditLogModel.create({
  actorUserId: admin.id,
  action: 'UPDATED_USER_ROLE',
  targetUserId: user.id,
  status: 'SUCCESS',
  ip: req.ip,
  userAgent: req.headers['user-agent'],
  details: { oldRole: 'USER', newRole: 'ADMIN' },
});
```

## Local Development
