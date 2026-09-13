import { createHash } from 'node:crypto';
import jwt from 'jsonwebtoken';

// Refresh token ke verified payload ka structure
export interface RefreshTokenPayload {
  userId: string;
  sessionId: string;
  type: 'refresh';
}

// Environment variable missing ho toh application ko clear error mile
function getRequiredSecret(
  name: 'JWT_ACCESS_SECRET' | 'JWT_REFRESH_SECRET'
) {
  const secret = process.env[name];

  if (!secret) {
    throw new Error(`${name} is not configured`);
  }

  return secret;
}

// Protected APIs ke liye short-lived access token
export function createAccessToken(user: { id: string; email: string }) {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      type: 'access',
    },
    getRequiredSecret('JWT_ACCESS_SECRET'),
    { expiresIn: '15m' }
  );
}

// Naya access token lene ke liye long-lived refresh token
export function createRefreshToken(userId: string, sessionId: string) {
  return jwt.sign(
    {
      userId,
      sessionId,
      type: 'refresh',
    },
    getRequiredSecret('JWT_REFRESH_SECRET'),
    { expiresIn: '7d' }
  );
}

// Refresh endpoint par token ki signature, expiry aur payload verify karega
export function verifyRefreshToken(token: string): RefreshTokenPayload {
  const payload = jwt.verify(
    token,
    getRequiredSecret('JWT_REFRESH_SECRET')
  );

  if (
    typeof payload === 'string' ||
    typeof payload.userId !== 'string' ||
    typeof payload.sessionId !== 'string' ||
    payload.type !== 'refresh'
  ) {
    throw new Error('Invalid refresh token');
  }

  return {
    userId: payload.userId,
    sessionId: payload.sessionId,
    type: 'refresh',
  };
}

// Raw refresh token database mein store nahi karenge
export function hashToken(token: string) {
  return createHash('sha256').update(token).digest('hex');
}

// Database session ki expiry JWT ke 7-day expiry ke saath match hogi
export function getRefreshTokenExpiry() {
  const sevenDays = 7 * 24 * 60 * 60 * 1000;

  return new Date(Date.now() + sevenDays);
}