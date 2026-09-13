import 'dotenv/config';

import { randomUUID } from 'node:crypto';
import express from 'express';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';

import { prisma } from './prisma';
import { AuthRequest, requireAuth } from './middleware/auth';
import {
  clearRefreshCookieOptions,
  refreshCookieOptions,
} from './config/cookies';
import {
  createAccessToken,
  createRefreshToken,
  getRefreshTokenExpiry,
  hashToken,
  verifyRefreshToken,
} from './utils/tokens';

const app = express();
const PORT = Number(process.env.PORT) || 4000;

// Client se aane wali JSON body ko req.body mein available karta hai
app.use(express.json());

// Client ki cookies ko req.cookies mein available karta hai
app.use(cookieParser());

// Express technology header hide karta hai
app.disable('x-powered-by');

// ─── Health check ───────────────────────────────
app.get('/health', (req, res) => {
  return res.json({ status: 'ok' });
});

// ─── Signup ────────────────────────────────────
app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: 'Email and password are required',
      });
    }

    // Plain password database mein store nahi karna
    const passwordHash = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
      },
    });

    // Response mein passwordHash return nahi karna
    return res.status(201).json({
      id: user.id,
      email: user.email,
      createdAt: user.createdAt,
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: 'Something went wrong',
    });
  }
});

// ─── Login and session creation ────────────────
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: 'Email and password are required',
      });
    }

    const user = await prisma.user.findUnique({
      where: { email },
    });

    // User missing aur wrong password ke liye same message
    if (!user) {
      return res.status(401).json({
        error: 'Invalid email or password',
      });
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!isPasswordValid) {
      return res.status(401).json({
        error: 'Invalid email or password',
      });
    }

    // Har login/device ko unique session milta hai
    const sessionId = randomUUID();

    const accessToken = createAccessToken(user);
    const refreshToken = createRefreshToken(user.id, sessionId);

    // Raw refresh token ki jagah uska hash store hota hai
    await prisma.session.create({
      data: {
        id: sessionId,
        userId: user.id,
        refreshTokenHash: hashToken(refreshToken),
        expiresAt: getRefreshTokenExpiry(),
      },
    });

    // Refresh token HTTP-only cookie mein jayega
    res.cookie(
      'refreshToken',
      refreshToken,
      refreshCookieOptions
    );

    return res.json({ accessToken });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: 'Something went wrong',
    });
  }
});

// ─── Refresh-token rotation ────────────────────
app.post('/refresh', async (req, res) => {
  const refreshToken = req.cookies.refreshToken as
    | string
    | undefined;

  if (!refreshToken) {
    return res.status(401).json({
      error: 'Refresh token required',
    });
  }

  try {
    // JWT signature, expiry aur payload verify karo
    const payload = verifyRefreshToken(refreshToken);

    // Token ke sessionId se session aur user fetch karo
    const session = await prisma.session.findUnique({
      where: {
        id: payload.sessionId,
      },
      include: {
        user: true,
      },
    });

    const now = new Date();

    // Session active, unexpired aur correct user ka hona chahiye
    if (
      !session ||
      session.userId !== payload.userId ||
      session.revokedAt ||
      session.expiresAt <= now
    ) {
      res.clearCookie(
        'refreshToken',
        clearRefreshCookieOptions
      );

      return res.status(401).json({
        error: 'Invalid refresh session',
      });
    }

    const currentTokenHash = hashToken(refreshToken);

    // Received token ka hash stored hash se match hona chahiye
    if (session.refreshTokenHash !== currentTokenHash) {
      // Old refresh token reuse detect hone par session revoke karo
      await prisma.session.updateMany({
        where: {
          id: session.id,
          revokedAt: null,
        },
        data: {
          revokedAt: now,
        },
      });

      res.clearCookie(
        'refreshToken',
        clearRefreshCookieOptions
      );

      return res.status(401).json({
        error: 'Invalid refresh session',
      });
    }

    // Rotation ke liye new token pair
    const nextRefreshToken = createRefreshToken(
      session.userId,
      session.id
    );

    const accessToken = createAccessToken(session.user);

    // Old hash match hone par hi session atomically update hoga
    const updatedSession = await prisma.session.updateMany({
      where: {
        id: session.id,
        refreshTokenHash: currentTokenHash,
        revokedAt: null,
        expiresAt: {
          gt: now,
        },
      },
      data: {
        refreshTokenHash: hashToken(nextRefreshToken),
      },
    });

    if (updatedSession.count !== 1) {
      res.clearCookie(
        'refreshToken',
        clearRefreshCookieOptions
      );

      return res.status(401).json({
        error: 'Invalid refresh session',
      });
    }

    // Browser ki old cookie ko new refresh token se replace karo
    res.cookie(
      'refreshToken',
      nextRefreshToken,
      refreshCookieOptions
    );

    return res.json({ accessToken });
  } catch {
    res.clearCookie(
      'refreshToken',
      clearRefreshCookieOptions
    );

    return res.status(401).json({
      error: 'Invalid or expired refresh token',
    });
  }
});

// ─── Logout route ────────────────────────────────
app.post('/logout', async (req, res) => {
  const refreshToken = req.cookies.refreshToken as string | undefined;

  if (refreshToken) {
    try {
      const payload = verifyRefreshToken(refreshToken);

      // Session ko delete nahi kar rahe; revoked mark kar rahe hain.
      // Isse security history aur audit information preserve rehti hai.
      await prisma.session.updateMany({
        where: {
          id: payload.sessionId,
          userId: payload.userId,
          refreshTokenHash: hashToken(refreshToken),
          revokedAt: null,
        },
        data: {
          revokedAt: new Date(),
        },
      });
    } catch {
      // Token invalid ho tab bhi logout successful dikhayenge.
      // Client ko token valid/invalid hone ki extra information nahi deni.
    }
  }

  // Browser/curl se refresh-token cookie remove karo.
  res.clearCookie('refreshToken', clearRefreshCookieOptions);

  // 204 = request successful, response body ki zarurat nahi.
  return res.status(204).send();
});



// ─── Current logged-in user ────────────────────
app.get('/me', requireAuth, async (req, res) => {
  try {
    // Middleware verified user ko request mein attach karta hai
    const authReq = req as AuthRequest;
    const userId = authReq.user!.userId;

    const user = await prisma.user.findUnique({
      where: {
        id: userId,
      },
      select: {
        id: true,
        email: true,
        createdAt: true,
      },
    });

    if (!user) {
      return res.status(404).json({
        error: 'User not found',
      });
    }

    return res.json({ user });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: 'Something went wrong',
    });
  }
});

// Saare routes register hone ke baad server start hota hai
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});