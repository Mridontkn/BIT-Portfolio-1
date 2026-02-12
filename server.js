const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const Stripe = require('stripe');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// IMPORTANT:
// Stripe webhook needs raw body for signature verification. :contentReference[oaicite:2]{index=2}
// So we mount the webhook route BEFORE express.json(), with express.raw().
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const stripe = Stripe(process.env.STRIPE_SECRET_KEY || '');
  const sig = req.headers['stripe-signature'];

  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET || ''
    );
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    // Checkout finished successfully
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;

      // We pass userId in metadata when creating the session
      const userId = parseInt(session.metadata?.userId, 10);
      if (!Number.isNaN(userId)) {
        const u = users.find(x => x.id === userId);
        if (u) {
          u.isPremium = true;
          u.stripeCustomerId = session.customer || null;
          u.stripeSubscriptionId = session.subscription || null;
          u.premiumSince = new Date();
          console.log(`User ${userId} upgraded to premium.`);
        }
      }
    }

    // Optional: handle subscription cancellations / changes
    // If you want to revoke premium when subscription is canceled:
    if (event.type === 'customer.subscription.deleted') {
      const sub = event.data.object;
      const u = users.find(x => x.stripeSubscriptionId === sub.id);
      if (u) {
        u.isPremium = false;
        console.log(`User ${u.id} premium revoked (subscription deleted).`);
      }
    }

    return res.json({ received: true });
  } catch (err) {
    console.error('Webhook handler error:', err);
    return res.status(500).json({ message: 'Webhook handler error' });
  }
});

// Middleware (after webhook)
app.use(cors());
app.use(express.json());

// Temporary in-memory storage (replace with database later)
let users = [];

// JWT
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// Stripe
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || '');

// Frontend origin
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:5500';

// Register endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = users.find(u => u.email === email);
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: users.length + 1,
      name,
      email,
      password: hashedPassword,
      createdAt: new Date(),
      isPremium: false
    };

    users.push(newUser);

    const token = jwt.sign(
      { userId: newUser.id, email: newUser.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: { id: newUser.id, name: newUser.name, email: newUser.email, createdAt: newUser.createdAt, isPremium: newUser.isPremium }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = users.find(u => u.email === email);
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, name: user.name, email: user.email, createdAt: user.createdAt, isPremium: user.isPremium }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = payload;
    next();
  });
};

// Protected route - profile
app.get('/api/profile', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ message: 'User not found' });

  res.json({
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt,
    isPremium: user.isPremium
  });
});

// Premium status (server source of truth)
app.get('/api/premium-status', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ message: 'User not found' });
  res.json({ isPremium: !!user.isPremium });
});

// Create Stripe Checkout Session (subscription)
app.post('/api/create-checkout-session', authenticateToken, async (req, res) => {
  try {
    const user = users.find(u => u.id === req.user.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    // You MUST create a recurring Price in Stripe Dashboard and put its ID in env.
    // Stripe subscriptions with Checkout require a recurring price. :contentReference[oaicite:3]{index=3}
    const priceId = process.env.STRIPE_PRICE_ID;
    if (!priceId) {
      return res.status(500).json({ message: 'Missing STRIPE_PRICE_ID in environment variables.' });
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${CLIENT_URL}/dashboard.html?checkout=success`,
      cancel_url: `${CLIENT_URL}/dashboard.html?checkout=cancel`,
      customer_email: user.email,
      metadata: {
        userId: String(user.id)
      }
    });

    // Checkout Session gives you a URL to redirect to Stripe-hosted page. :contentReference[oaicite:4]{index=4}
    return res.json({ url: session.url });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Failed to create checkout session' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
