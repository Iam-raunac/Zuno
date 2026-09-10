import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';

export interface AuthRequest extends Request {
  user?: {
    userId: string;
    email: string;
  };
}

export function requireAuth(
  req: AuthRequest,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Authentication required',
    });
  }

  const token = authHeader.slice(7);

  try {
    const payload = jwt.verify(
      token,
      process.env.JWT_ACCESS_SECRET as string
    );

    if (
      typeof payload === 'string' ||
      typeof payload.userId !== 'string' ||
      typeof payload.email !== 'string'
    ) {
      return res.status(401).json({
        error: 'Invalid access token',
      });
    }

    req.user = {
      userId: payload.userId,
      email: payload.email,
    };

    next();
  } catch {
    return res.status(401).json({
      error: 'Invalid or expired access token',
    });
  }
}