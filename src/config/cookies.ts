import { CookieOptions } from 'express';

const sevenDays = 7 * 24 * 60 * 60 * 1000;

// Login aur refresh ke time refresh-token cookie set karne ke options
export const refreshCookieOptions: CookieOptions = {
  httpOnly: true, // Frontend JavaScript token read nahi kar sakta
  secure: process.env.NODE_ENV === 'production', // Production mein only HTTPS
  sameSite: 'strict', // Cross-site requests se protection
  path: '/',
  maxAge: sevenDays,
};

// Logout ke time same options ke saath cookie clear karni hogi
export const clearRefreshCookieOptions: CookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  path: '/',
};