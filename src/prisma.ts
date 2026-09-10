import { PrismaClient } from './generated/prisma';
import { PrismaPg } from '@prisma/adapter-pg';

// PrismaClient ko batana padta hai ki database se KAISE connect
// karna hai — isके liye ek "adapter" chahiye (Prisma 7 ka naya tareeka).
const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL });

// Ek hi PrismaClient poore app mein use karenge.
export const prisma = new PrismaClient({ adapter });