import jwt from 'jsonwebtoken';
import 'dotenv/config';
import express from 'express';
import bcrypt from 'bcryptjs';
import { prisma } from './prisma';

const app = express();
const PORT = 4000;

// Yeh line zaroori hai — bina iske Express request ke JSON
// body ko samajh nahi paayega (req.body undefined aayega)
app.use(express.json());

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// ─── Signup route ───────────────────────────────
app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Step 1: Basic check — email aur password diye hain ya nahi
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Step 2: Password ko hash karo — asli password kabhi save nahi karenge
    const passwordHash = await bcrypt.hash(password, 10);

    // Step 3: Database mein naya user create karo
    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
      },
    });

    // Step 4: Response mein passwordHash kabhi mat bhejo (chahe hashed ho)
    res.status(201).json({
      id: user.id,
      email: user.email,
      createdAt: user.createdAt,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// ─── Login route ───────────────────────────────
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Step 1: User ko email se dhoondo
    const user = await prisma.user.findUnique({ where: { email } });

    // Step 2: Agar user hi nahi mila, generic error do
    // (Yeh "email nahi mila" vs "password galat" alag-alag mat batao —
    //  isse attacker ko pata chal jaata hai konse emails registered hain)
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Step 3: Diya gaya password, saved hash se compare karo
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Step 4: Password sahi hai — ab JWT token banao
    const accessToken = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_ACCESS_SECRET as string,
      { expiresIn: '15m' }
    );

    res.json({ accessToken });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});