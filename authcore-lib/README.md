# AuthCore

AuthCore is a plug-and-play authentication and RBAC library for Express + MongoDB.

It gives you:
- JWT access and refresh token flow
- Role-based authorization
- Permission-based authorization
- MongoDB adapter and schemas
- Production-friendly middleware and error handling

## Install

```bash
npm install authcore express mongoose cookie-parser jsonwebtoken bcrypt
```

For TypeScript projects:

```bash
npm install -D typescript @types/express @types/cookie-parser @types/node
```

## 5-Minute Setup

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

## Local Development for This Repo

```bash
npm install
npm run build
npm run test
npm run dev
```

Open:
- http://localhost:3000

## Publishing

```bash
npm login
npm run test
npm run build
npm publish --access public
```

This package is configured with:
- prepare script so git installs auto-build
- prepublishOnly checks to prevent publishing broken builds

## Troubleshooting

- Login fails with invalid token secret:
  - Ensure ACCESS_SECRET and REFRESH_SECRET are set and consistent.
- Mongo connection fails:
  - Verify MONGODB_URI and network access to DB.
- Protected route returns 401:
  - Send Authorization header: Bearer <accessToken>.
- Refresh returns 401:
  - Ensure refresh cookie is being set and sent with credentials.
