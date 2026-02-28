# Implementation Paper: AuthCore Library

## 1. Abstract & System Overview
**AuthCore** is a reusable, stateless Node.js and Express library designed specifically for handling robust authentication and Role-Based Access Control (RBAC). Designed as a plug-and-play developer tool, the library relies on JSON Web Tokens (JWT) for session management and employs a centralized access policy engine to enforce authorization rules across various application endpoints.

Building a developer-facing library rather than a standard CRUD application demonstrates advanced software engineering concepts, including design patterns (Adapter Pattern), security (Refresh Token Rotation), and tooling in the modern JavaScript ecosystem (dual ESM/CJS builds).

---

## 2. Architectural Strategies and Design Considerations

### 2.1 Database Agnosticism via the Adapter Pattern
The library utilizes the **Adapter Design Pattern** to act as a bridge between incompatible interfaces. This ensures the core authentication logic never dictates the consuming application's database or ORM choice (e.g., MongoDB, PostgreSQL, Prisma, TypeORM). The adapter normalizes data layer operations to common interfaces that the library's internal logic can interact with securely.

### 2.2 Centralized RBAC
Instead of scattering conditional permission checks inside individual API route handlers, the library implements a centralized policy engine. This evaluates user roles against explicitly required permissions at the middleware layer, resulting in a system whose behavior is stable, clean, and highly auditable.

### 2.3 Module Compatibility & Build Strategy
The package is built to simultaneously support both ECMAScript Modules (ESM) and legacy CommonJS (CJS) environments, maximizing compatibility. We utilize `tsup` for an optimized, rapid build process.

---

## 3. Directory Taxonomy and Setup

A professional NPM package requires a strict folder structure to isolate source code from distribution artifacts. 

```text
/authcore-lib
├── /src
│   ├── /adapter       # Database abstract interfaces
│   ├── /crypto        # Hashing and JWT logic
│   ├── /middleware    # Express auth, RBAC, and error handlers
│   ├── /types         # TS Declaration merging
│   └── index.ts       # Main export file
├── /tests             # Automated unit and integration tests
├── .npmignore         # Excludes raw source from the published NPM package
├── package.json       # Project manifest and export definitions
├── tsconfig.json      # TypeScript compiler configurations
└── tsup.config.ts     # Bundler configuration for generating ESM/CJS outputs
```

---

## 4. Core System Implementation

### 4.1 Build and Packaging Configuration

To ensure the library resolves correctly for various module loaders, the package manifest utilizes the modern `exports` field:

**`package.json` (Excerpts)**
```json
{
  "name": "authcore",
  "version": "1.0.0",
  "main": "./dist/index.js",
  "module": "./dist/index.mjs",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "require": "./dist/index.js",
      "import": "./dist/index.mjs",
      "types": "./dist/index.d.ts"
    }
  },
  "scripts": {
    "build": "tsup",
    "test": "vitest"
  }
}
```

**`tsup.config.ts`**
```typescript
import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'], // Dual output formats
  dts: true,              // Emits TypeScript declaration files (.d.ts)
  splitting: false,
  sourcemap: true,
  clean: true,            // Cleans the /dist folder before every build
});
```

### 4.2 The Database Adapter Interface

We define the exact contract that the consuming application must fulfill to interact with AuthCore.

**`src/adapter/DatabaseAdapter.ts`**
```typescript
export interface UserPayload {
  id: string;
  role: string;
  email: string;
}

export interface AuthDatabaseAdapter {
  // Fetch a user from the specific database implementation
  getUserByEmail(email: string): Promise<UserPayload | null>;
  
  // Refresh token management for ROT (Refresh Token Rotation)
  saveRefreshToken(userId: string, hashedToken: string): Promise<void>;
  revokeRefreshToken(userId: string, hashedToken: string): Promise<void>;
}
```

### 4.3 MongoDB & Mongoose Context (Adapter Implementation)

As per the system design, the library natively supports Node.js and MongoDB by providing a Mongoose-specific adapter. Rather than compiling the models directly, the library exports Mongoose schemas, allowing the consuming application to instantiate the models using their own database connection patterns.

**`src/adapter/MongoSchemas.ts`**
```typescript
import { Schema } from 'mongoose';

export const UserSchema = new Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'USER' },
  refreshTokens: [{ type: String }] // Stores hashed refresh tokens for RTR
}, { timestamps: true });
```

**`src/adapter/MongoAuthAdapter.ts`**
```typescript
import { Model } from 'mongoose';
import { AuthDatabaseAdapter, UserPayload } from './DatabaseAdapter';

export class MongoAuthAdapter implements AuthDatabaseAdapter {
  constructor(private UserModel: Model<any>) {}

  async getUserByEmail(email: string): Promise<UserPayload | null> {
    const user = await this.UserModel.findOne({ email }).lean();
    if (!user) return null;
    
    return {
      id: user._id.toString(),
      role: user.role,
      email: user.email
    };
  }

  async saveRefreshToken(userId: string, hashedToken: string): Promise<void> {
    await this.UserModel.findByIdAndUpdate(userId, {
      $push: { refreshTokens: hashedToken }
    });
  }

  async revokeRefreshToken(userId: string, hashedToken: string): Promise<void> {
    await this.UserModel.findByIdAndUpdate(userId, {
      $pull: { refreshTokens: hashedToken }
    });
  }
}
```

### 4.4 Security and Cryptography Module

Passwords must never be stored in plain text. This module handles bcrypt hashing and JWT generation.

**`src/crypto/tokens.ts`**
```typescript
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

export class CryptoService {
  constructor(private accessSecret: string, private refreshSecret: string) {}

  generateAccessToken(payload: object) {
    return jwt.sign(payload, this.accessSecret, { expiresIn: '15m' }); // Short-lived
  }

  generateRefreshToken(payload: object) {
    return jwt.sign(payload, this.refreshSecret, { expiresIn: '7d' }); // Long-lived
  }

  async hashData(data: string): Promise<string> {
    const saltRounds = 10;
    return bcrypt.hash(data, saltRounds);
  }

  async compareData(data: string, hash: string): Promise<boolean> {
    return bcrypt.compare(data, hash);
  }
}
```

### 4.5 Express Integration & Request Augmentation

To seamlessly type the custom user payload on the Express Request object, we utilize TypeScript declaration merging.

**`src/types/express.d.ts`**
```typescript
import { UserPayload } from '../adapter/DatabaseAdapter';

// Merges our custom property into the global Express Request interface
declare global {
  namespace Express {
    interface Request {
      user?: UserPayload;
    }
  }
}
```

### 4.6 Authorization and RBAC Middleware

The policy engine checks session validity and verifies roles against route boundaries.

**`src/middleware/auth.ts`**
```typescript
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export const requireAuth = (secret: string) => {
  return (req: Request, res: Response, next: NextFunction) => {
    // Extract token from Authorization header (Bearer pattern)
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Authentication required. Token missing.' });
    }

    try {
      const decoded = jwt.verify(token, secret);
      req.user = decoded as any; // Attached populated payload to request
      next();
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired access token.' });
    }
  };
};

export const requireRole = (allowedRoles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    // Failsafe in case requireAuth wasn't placed before this middleware
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden: Insufficient permissions.' });
    }
    
    next();
  };
};
```

### 4.7 Asynchronous Error Handling

To catch async errors and forward them smoothly to Express's global handler, we implement standard wrapper classes.

**`src/middleware/errorHandler.ts`**
```typescript
import { Request, Response, NextFunction } from 'express';

// Custom Application Error
export class AppError extends Error {
  constructor(public statusCode: number, public message: string) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// Wrapper to automatically pass async promise rejections to next()
export const catchAsync = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// Global Express Error Middleware
export const globalErrorHandler = (
  err: any, 
  req: Request, 
  res: Response, 
  next: NextFunction
) => {
  const statusCode = err.statusCode || 500;
  res.status(statusCode).json({
    status: 'error',
    message: err.message || 'Internal Server Error'
  });
};
```

---

## 5. Security Summary & Best Practices Enforced

When implementing consuming code with AuthCore, the following mechanisms are adhered to:
1. **Refresh Token Rotation (RTR):** Every time a refresh token is used, the system should issue a new one and invalidate the old one. If an invalidated refresh token is ever presented, the adapter should revoke all tokens for that user stream.
2. **HTTP-Only Cookies:** The library's documentation mandates that refresh tokens be stored strictly within HTTP-Only, secure, SameSite cookies to mitigate Cross-Site Scripting (XSS).
3. **Short-lived Access Tokens:** Access tokens are distributed in-memory to React/Angular frontends and only survive for 10-15 minutes, limiting the window of exposure if a token is intercepted.

---

## 6. Real-World Integration Example

Here is how a developer consuming your library in a MongoDB project would implement it:

```typescript
import express from 'express';
import mongoose from 'mongoose';
import { requireAuth, requireRole, catchAsync } from 'authcore';
import { MongoAuthAdapter, UserSchema } from 'authcore/adapter'; 

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

// Connect to MongoDB and instantiate the user model using the schema from the library
mongoose.connect('mongodb://localhost:27017/my_app_db');
const UserModel = mongoose.model('User', UserSchema);

// Instantiate the adapter with the active model connection
const authAdapter = new MongoAuthAdapter(UserModel);
// *authAdapter can now be used in your login/register controllers

// An endpoint only Admin users can access
app.post(
  '/api/v1/system/config',
  requireAuth(JWT_SECRET),
  requireRole(['ADMIN']),
  catchAsync(async (req, res) => {
    // Business logic...
    res.json({ message: `Welcome Admin ${req.user.email}` });
  })
);
```

## Conclusion
The AuthCore library abstracts highly sensitive and complex security mechanisms into clean, reusable middleware routines. Its usage of advanced TypeScript constructs, design patterns, and rigorous dependency management makes it a production-ready package highlighting significant backend engineering competence.
