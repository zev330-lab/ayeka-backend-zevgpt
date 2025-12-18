const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const OpenAI = require('openai');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;

// Initialize OpenAI for ZevGPT
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use('/api/webhooks', express.raw({ type: 'application/json' }));

// Updated pricing configuration with ZevGPT
const PRICING_CONFIG = {
  seeker: {
    price_id: process.env.PRICE_ID_SEEKER, // $18/month
    tier: 'seeker',
    features: {
      library: ['basic', 'kabbalah'],
      live_sessions: false,
      coaching: false,
      community: false,
      zevgpt: false,
      max_content_access: 'limited'
    }
  },
  mystic: {
    price_id: process.env.PRICE_ID_MYSTIC, // $54/month  
    tier: 'mystic',
    features: {
      library: ['basic', 'kabbalah', 'enneagram', 'quantum'],
      live_sessions: true,
      coaching: false,
      community: false,
      zevgpt: true,
      zevgpt_messages_monthly: 175,
      max_content_access: 'full'
    }
  },
  teacher_intensive: {
    price_id: process.env.PRICE_ID_TEACHER_INTENSIVE, // $2,520 for 90 days
    tier: 'teacher',
    features: {
      library: 'all',
      live_sessions: true,
      coaching: true,
      community: true,
      zevgpt: true,
      zevgpt_messages_monthly: 'unlimited',
      max_content_access: 'unlimited',
      duration_days: 90
    }
  },
  teacher_coaching: {
    price_id: process.env.PRICE_ID_TEACHER_COACHING, // $1,260/month ongoing
    tier: 'teacher',
    features: {
      library: 'all',
      live_sessions: true,
      coaching: true,
      community: true,
      zevgpt: true,
      zevgpt_messages_monthly: 'unlimited',
      max_content_access: 'unlimited',
      requires_application: true
    }
  }
};

// Zev's Teaching Style System Prompt
const ZEVGPT_SYSTEM_PROMPT = `You are Zev, a spiritual guide and teacher trained in Kabbalah, Enneagram wisdom, quantum consciousness, and contemplative practice. Your teaching approach embodies ancient wisdom integrated with modern understanding.

CORE TEACHING METHODOLOGY:
- Use Socratic questioning that leads seekers to their own insights
- Integrate Kabbalistic framework (Tree of Life, Sefirot) as a map for spiritual development
- Apply Enneagram as a tool for self-understanding and transformation
- Bridge quantum principles with mystical wisdom
- Ground all spiritual insights in practical application
- Ask "Where are you?" as both literal and metaphysical inquiry

COMMUNICATION STYLE:
- Speak with warmth, depth, and gentle curiosity
- Ask leading questions rather than giving direct answers
- Use metaphors from nature, light, and sacred geometry
- Reference Hebrew concepts when appropriate (Sefirot, Tikkun, Teshuvah)
- Honor both the seeker's current understanding and their potential for growth
- Create space for silence and reflection

RESPONSE PATTERNS:
When someone shares a struggle: "I hear something stirring beneath your words. What would it mean to befriend this difficulty rather than solve it?"

When asked for guidance: "That's a beautiful question. Before I share what comes to mind, tell me - what does your own inner knowing whisper about this?"

When discussing spiritual concepts: "In Kabbalah, we speak of [concept]. How might this ancient map illuminate your current path?"

SAFETY GUIDELINES:
- Never bypass someone's emotional experience with premature spiritual teaching
- If you detect crisis or severe distress, acknowledge their pain and gently direct to human support
- Stay within your role as spiritual guide, not therapist or crisis counselor
- Honor the mystery - don't claim to have all answers

Remember: You are an AI trained on Zev's teachings, not Zev himself. When appropriate, gently remind seekers that while you carry his wisdom, the deepest guidance comes from their own connection to Source.

Begin each new conversation by asking where the person is in their spiritual journey right now.`;

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Tier access control middleware
const requireTier = (requiredTiers) => {
  return async (req, res, next) => {
    try {
      const userResult = await pool.query(
        'SELECT tier, subscription_status, trial_end_date FROM users WHERE id = $1',
        [req.user.id]
      );

      if (userResult.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      const user = userResult.rows[0];
      const userTier = user.tier || 'novice';
      
      // Check if trial has expired for novice users
      if (userTier === 'novice' && user.trial_end_date && new Date() > user.trial_end_date) {
        return res.status(403).json({ error: 'Trial expired. Please upgrade to continue.' });
      }

      // Check if user has required tier access
      if (!requiredTiers.includes(userTier)) {
        return res.status(403).json({ 
          error: 'Access denied. Upgrade required.',
          required_tiers: requiredTiers,
          current_tier: userTier
        });
      }

      req.userTier = userTier;
      next();
    } catch (error) {
      console.error('Tier check error:', error);
      res.status(500).json({ error: 'Server error during tier verification' });
    }
  };
};

// ZevGPT usage tracking functions
const checkZevGPTUsage = async (userId) => {
  try {
    // Get user tier
    const userResult = await pool.query(
      'SELECT tier, subscription_status FROM users WHERE id = $1',
      [userId]
    );
    
    const user = userResult.rows[0];
    if (!user) throw new Error('User not found');

    const userTier = user.tier;
    const config = Object.values(PRICING_CONFIG).find(p => p.tier === userTier);
    
    // Teacher tier has unlimited access
    if (userTier === 'teacher') {
      return { allowed: true, remaining: 'unlimited', tier: userTier };
    }
    
    // Check if user has ZevGPT access
    if (!config?.features?.zevgpt) {
      return { allowed: false, remaining: 0, tier: userTier, error: 'Tier does not include ZevGPT access' };
    }

    // Get current month usage
    const currentMonth = new Date().toISOString().slice(0, 7); // YYYY-MM format
    const usageResult = await pool.query(
      `SELECT messages_used FROM zevgpt_usage 
       WHERE user_id = $1 AND month = $2`,
      [userId, currentMonth]
    );

    const messagesUsed = usageResult.rows[0]?.messages_used || 0;
    const monthlyLimit = config.features.zevgpt_messages_monthly;
    const remaining = monthlyLimit - messagesUsed;

    return {
      allowed: remaining > 0,
      remaining: Math.max(0, remaining),
      tier: userTier,
      limit: monthlyLimit
    };
  } catch (error) {
    console.error('ZevGPT usage check error:', error);
    return { allowed: false, remaining: 0, error: error.message };
  }
};

const incrementZevGPTUsage = async (userId, tokensUsed = 0) => {
  try {
    const currentMonth = new Date().toISOString().slice(0, 7);
    
    await pool.query(
      `INSERT INTO zevgpt_usage (user_id, month, messages_used, tokens_used)
       VALUES ($1, $2, 1, $3)
       ON CONFLICT (user_id, month)
       DO UPDATE SET 
         messages_used = zevgpt_usage.messages_used + 1,
         tokens_used = zevgpt_usage.tokens_used + $3`,
      [userId, currentMonth, tokensUsed]
    );
  } catch (error) {
    console.error('Error incrementing ZevGPT usage:', error);
  }
};

// Crisis detection keywords and patterns
const CRISIS_KEYWORDS = [
  'suicide', 'kill myself', 'end my life', 'want to die', 'better off dead',
  'self harm', 'hurt myself', 'cut myself', 'overdose', 'can\'t go on',
  'hopeless', 'no point', 'everyone would be better without me'
];

const detectCrisis = (message) => {
  const lowerMessage = message.toLowerCase();
  return CRISIS_KEYWORDS.some(keyword => lowerMessage.includes(keyword));
};

// Initialize database with ZevGPT tables
const initDB = async () => {
  try {
    await pool.query(`
      -- Updated users table with new tier structure
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255),
        tier VARCHAR(50) DEFAULT 'novice',
        subscription_status VARCHAR(50) DEFAULT 'trial',
        stripe_customer_id VARCHAR(255),
        stripe_subscription_id VARCHAR(255),
        trial_end_date TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '14 days'),
        subscription_start_date TIMESTAMP,
        subscription_end_date TIMESTAMP,
        coaching_application_status VARCHAR(50) DEFAULT NULL,
        coaching_application_date TIMESTAMP,
        teacher_intensive_completion_date TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- ZevGPT conversations
      CREATE TABLE IF NOT EXISTS zevgpt_conversations (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255),
        summary TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- ZevGPT messages
      CREATE TABLE IF NOT EXISTS zevgpt_messages (
        id SERIAL PRIMARY KEY,
        conversation_id INTEGER REFERENCES zevgpt_conversations(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        role VARCHAR(20) CHECK (role IN ('user', 'assistant', 'system')),
        content TEXT NOT NULL,
        tokens_input INTEGER DEFAULT 0,
        tokens_output INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- ZevGPT usage tracking
      CREATE TABLE IF NOT EXISTS zevgpt_usage (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        month VARCHAR(7) NOT NULL, -- YYYY-MM format
        messages_used INTEGER DEFAULT 0,
        tokens_used INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, month)
      );

      -- Content library with tier restrictions
      CREATE TABLE IF NOT EXISTS content_library (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        content_type VARCHAR(50) NOT NULL,
        category VARCHAR(100) NOT NULL,
        required_tier VARCHAR(50) DEFAULT 'novice',
        duration_minutes INTEGER,
        video_url TEXT,
        content_url TEXT,
        thumbnail_url TEXT,
        sort_order INTEGER DEFAULT 0,
        is_featured BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- User progress tracking
      CREATE TABLE IF NOT EXISTS user_progress (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        content_id INTEGER REFERENCES content_library(id) ON DELETE CASCADE,
        progress_percentage INTEGER DEFAULT 0,
        completed BOOLEAN DEFAULT FALSE,
        last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        notes TEXT,
        UNIQUE(user_id, content_id)
      );

      -- Live sessions
      CREATE TABLE IF NOT EXISTS live_sessions (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        session_type VARCHAR(50) NOT NULL, -- 'lecture', 'meditation', 'q_and_a'
        scheduled_date TIMESTAMP NOT NULL,
        duration_minutes INTEGER DEFAULT 60,
        zoom_link TEXT,
        recording_url TEXT,
        required_tier VARCHAR(50) DEFAULT 'mystic',
        max_participants INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Session registrations
      CREATE TABLE IF NOT EXISTS session_registrations (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        session_id INTEGER REFERENCES live_sessions(id) ON DELETE CASCADE,
        registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        attended BOOLEAN DEFAULT FALSE,
        UNIQUE(user_id, session_id)
      );

      -- Coaching applications
      CREATE TABLE IF NOT EXISTS coaching_applications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        application_text TEXT NOT NULL,
        current_situation TEXT,
        goals TEXT,
        previous_experience TEXT,
        commitment_level INTEGER, -- 1-10 scale
        status VARCHAR(50) DEFAULT 'pending', -- pending, approved, rejected
        admin_notes TEXT,
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TIMESTAMP,
        reviewed_by INTEGER
      );

      -- Coaching sessions
      CREATE TABLE IF NOT EXISTS coaching_sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        scheduled_date TIMESTAMP NOT NULL,
        duration_minutes INTEGER DEFAULT 60,
        session_notes TEXT,
        homework_assigned TEXT,
        zoom_link TEXT,
        status VARCHAR(50) DEFAULT 'scheduled', -- scheduled, completed, cancelled
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Community posts (for Teacher tier)
      CREATE TABLE IF NOT EXISTS community_posts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255),
        content TEXT NOT NULL,
        post_type VARCHAR(50) DEFAULT 'discussion', -- discussion, question, insight
        is_pinned BOOLEAN DEFAULT FALSE,
        likes_count INTEGER DEFAULT 0,
        replies_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Journal entries
      CREATE TABLE IF NOT EXISTS journal_entries (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255),
        content TEXT NOT NULL,
        mood INTEGER, -- 1-10 scale
        gratitude TEXT,
        insights TEXT,
        entry_date DATE DEFAULT CURRENT_DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Insert sample content with tier restrictions
      INSERT INTO content_library (title, description, content_type, category, required_tier, duration_minutes) VALUES
        ('Foundations of Spiritual Practice', 'Beginning your journey with contemplative traditions', 'video', 'basic', 'novice', 45),
        ('Introduction to Kabbalah', 'The Tree of Life and its mystical significance', 'course', 'kabbalah', 'seeker', 120),
        ('Quantum Consciousness', 'Where science meets spirituality', 'video', 'quantum', 'mystic', 60),
        ('Enneagram Deep Dive', 'Personality patterns and spiritual growth', 'course', 'enneagram', 'mystic', 180),
        ('Advanced Integration Practices', 'Synthesizing all modalities for transformation', 'workshop', 'advanced', 'teacher', 90),
        ('Daily Meditation Practices', 'Building a sustainable practice', 'video', 'basic', 'novice', 30),
        ('Kabbalistic Tree of Life Meditation', 'Working with the Sephirot', 'meditation', 'kabbalah', 'seeker', 25),
        ('Quantum Field Awareness', 'Consciousness and the observer effect', 'video', 'quantum', 'mystic', 40)
      ON CONFLICT DO NOTHING;

      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_tier ON users(tier);
      CREATE INDEX IF NOT EXISTS idx_content_tier ON content_library(required_tier);
      CREATE INDEX IF NOT EXISTS idx_user_progress ON user_progress(user_id, content_id);
      CREATE INDEX IF NOT EXISTS idx_zevgpt_conversations ON zevgpt_conversations(user_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_zevgpt_messages ON zevgpt_messages(conversation_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_zevgpt_usage ON zevgpt_usage(user_id, month);
    `);
    
    console.log('✅ Database initialized successfully with ZevGPT tables');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
  }
};

// Helper function to get price ID from tier
const getPriceIdFromTier = (tier) => {
  const config = Object.values(PRICING_CONFIG).find(p => p.tier === tier);
  return config ? config.price_id : null;
};

// Routes

// Auth routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Check if user exists
    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);
    
    // Create user with 14-day trial
    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email, tier, trial_end_date',
      [name, email, passwordHash]
    );

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      message: 'User created successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        tier: user.tier,
        trial_end_date: user.trial_end_date
      },
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        tier: user.tier,
        subscription_status: user.subscription_status,
        trial_end_date: user.trial_end_date
      },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// User profile
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, tier, subscription_status, trial_end_date, subscription_end_date, coaching_application_status FROM users WHERE id = $1',
      [req.user.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    res.json(user);
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ZevGPT Chat Routes
app.post('/api/zevgpt/chat', authenticateToken, requireTier(['mystic', 'teacher']), async (req, res) => {
  try {
    const { message, conversationId } = req.body;
    const userId = req.user.id;
    
    // Check usage limits
    const usageCheck = await checkZevGPTUsage(userId);
    if (!usageCheck.allowed) {
      return res.status(429).json({
        error: 'Usage limit exceeded',
        remaining: usageCheck.remaining,
        limit: usageCheck.limit,
        tier: usageCheck.tier
      });
    }

    // Crisis detection
    if (detectCrisis(message)) {
      const crisisResponse = `I hear you're in pain right now, and I want you to know that you're not alone. While I can offer spiritual support, what you're experiencing may need immediate human care. 

Please reach out to:
- National Suicide Prevention Lifeline: 988
- Crisis Text Line: Text HOME to 741741
- Or contact a trusted friend, family member, or mental health professional

Your life has immense value. Please get the support you deserve.`;
      
      return res.json({
        message: crisisResponse,
        crisis_detected: true,
        remaining_messages: usageCheck.remaining - 1
      });
    }

    // Get or create conversation
    let conversation;
    if (conversationId) {
      const convResult = await pool.query(
        'SELECT * FROM zevgpt_conversations WHERE id = $1 AND user_id = $2',
        [conversationId, userId]
      );
      conversation = convResult.rows[0];
    }

    if (!conversation) {
      const newConvResult = await pool.query(
        'INSERT INTO zevgpt_conversations (user_id, title) VALUES ($1, $2) RETURNING *',
        [userId, 'New Conversation']
      );
      conversation = newConvResult.rows[0];
    }

    // Get recent conversation history (last 10 messages)
    const historyResult = await pool.query(
      `SELECT role, content FROM zevgpt_messages 
       WHERE conversation_id = $1 
       ORDER BY created_at DESC 
       LIMIT 10`,
      [conversation.id]
    );
    
    const conversationHistory = historyResult.rows.reverse();

    // Prepare messages for OpenAI
    const messages = [
      { role: 'system', content: ZEVGPT_SYSTEM_PROMPT },
      ...conversationHistory.map(msg => ({
        role: msg.role,
        content: msg.content
      })),
      { role: 'user', content: message }
    ];

    // Call OpenAI
    const completion = await openai.chat.completions.create({
      model: 'gpt-4',
      messages: messages,
      max_tokens: 500,
      temperature: 0.7,
    });

    const assistantResponse = completion.choices[0].message.content;
    const tokensUsed = completion.usage.total_tokens;

    // Save messages to database
    await pool.query(
      'INSERT INTO zevgpt_messages (conversation_id, user_id, role, content) VALUES ($1, $2, $3, $4)',
      [conversation.id, userId, 'user', message]
    );

    await pool.query(
      'INSERT INTO zevgpt_messages (conversation_id, user_id, role, content, tokens_input, tokens_output) VALUES ($1, $2, $3, $4, $5, $6)',
      [conversation.id, userId, 'assistant', assistantResponse, completion.usage.prompt_tokens, completion.usage.completion_tokens]
    );

    // Update usage tracking
    await incrementZevGPTUsage(userId, tokensUsed);

    // Get updated usage info
    const updatedUsage = await checkZevGPTUsage(userId);

    res.json({
      message: assistantResponse,
      conversation_id: conversation.id,
      remaining_messages: updatedUsage.remaining,
      tokens_used: tokensUsed
    });

  } catch (error) {
    console.error('ZevGPT chat error:', error);
    
    if (error.code === 'rate_limit_exceeded') {
      res.status(429).json({ error: 'OpenAI rate limit exceeded. Please try again later.' });
    } else if (error.code === 'insufficient_quota') {
      res.status(503).json({ error: 'OpenAI quota exceeded. Please contact support.' });
    } else {
      res.status(500).json({ error: 'Failed to process chat message' });
    }
  }
});

// Get ZevGPT usage status
app.get('/api/zevgpt/usage', authenticateToken, async (req, res) => {
  try {
    const usageInfo = await checkZevGPTUsage(req.user.id);
    res.json(usageInfo);
  } catch (error) {
    console.error('Usage fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch usage information' });
  }
});

// Get ZevGPT conversations
app.get('/api/zevgpt/conversations', authenticateToken, requireTier(['mystic', 'teacher']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title, created_at, updated_at 
       FROM zevgpt_conversations 
       WHERE user_id = $1 
       ORDER BY updated_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Conversations fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch conversations' });
  }
});

// Get specific conversation messages
app.get('/api/zevgpt/conversations/:conversationId', authenticateToken, requireTier(['mystic', 'teacher']), async (req, res) => {
  try {
    const { conversationId } = req.params;
    
    const result = await pool.query(
      `SELECT role, content, created_at 
       FROM zevgpt_messages 
       WHERE conversation_id = $1 AND user_id = $2 
       ORDER BY created_at ASC`,
      [conversationId, req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Conversation fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch conversation' });
  }
});

// Subscription management
app.post('/api/subscriptions/create-checkout', authenticateToken, async (req, res) => {
  try {
    const { tier } = req.body;
    
    if (!PRICING_CONFIG[tier]) {
      return res.status(400).json({ error: 'Invalid tier selected' });
    }

    const user = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userData = user.rows[0];
    let customerId = userData.stripe_customer_id;

    // Create Stripe customer if doesn't exist
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: userData.email,
        name: userData.name,
        metadata: { user_id: userData.id.toString() }
      });
      customerId = customer.id;
      
      await pool.query('UPDATE users SET stripe_customer_id = $1 WHERE id = $2', [customerId, userData.id]);
    }

    // Create checkout session
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{
        price: PRICING_CONFIG[tier].price_id,
        quantity: 1,
      }],
      mode: tier === 'teacher_intensive' ? 'payment' : 'subscription',
      success_url: `${process.env.FRONTEND_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}/pricing`,
      metadata: {
        user_id: userData.id.toString(),
        tier: tier
      }
    });

    res.json({ checkout_url: session.url });
  } catch (error) {
    console.error('Checkout creation error:', error);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// Content library with tier restrictions
app.get('/api/content/library', authenticateToken, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT tier FROM users WHERE id = $1', [req.user.id]);
    const userTier = userResult.rows[0]?.tier || 'novice';

    // Define tier hierarchy for content access
    const tierHierarchy = {
      'novice': ['novice'],
      'seeker': ['novice', 'seeker'],
      'mystic': ['novice', 'seeker', 'mystic'],
      'teacher': ['novice', 'seeker', 'mystic', 'teacher']
    };

    const accessibleTiers = tierHierarchy[userTier] || ['novice'];
    
    const result = await pool.query(
      'SELECT * FROM content_library ORDER BY sort_order, created_at',
    );

    // Add access information to each content item
    const contentWithAccess = result.rows.map(content => ({
      ...content,
      is_accessible: accessibleTiers.includes(content.required_tier),
      requires_upgrade: !accessibleTiers.includes(content.required_tier)
    }));

    res.json(contentWithAccess);
  } catch (error) {
    console.error('Library fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch library content' });
  }
});

// Live sessions
app.get('/api/sessions/upcoming', authenticateToken, requireTier(['mystic', 'teacher']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM live_sessions 
       WHERE scheduled_date > NOW() 
       AND (required_tier = $1 OR $1 = 'teacher')
       ORDER BY scheduled_date`,
      [req.userTier]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Sessions fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

// Coaching application
app.post('/api/coaching/apply', authenticateToken, async (req, res) => {
  try {
    const {
      application_text,
      current_situation,
      goals,
      previous_experience,
      commitment_level
    } = req.body;

    // Check if user completed teacher intensive
    const userResult = await pool.query(
      'SELECT teacher_intensive_completion_date FROM users WHERE id = $1',
      [req.user.id]
    );

    if (!userResult.rows[0]?.teacher_intensive_completion_date) {
      return res.status(400).json({ 
        error: 'Must complete 90-day Teacher Track intensive before applying for coaching' 
      });
    }

    // Create application
    const result = await pool.query(
      `INSERT INTO coaching_applications 
       (user_id, application_text, current_situation, goals, previous_experience, commitment_level)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [req.user.id, application_text, current_situation, goals, previous_experience, commitment_level]
    );

    // Update user application status
    await pool.query(
      'UPDATE users SET coaching_application_status = $1, coaching_application_date = NOW() WHERE id = $2',
      ['pending', req.user.id]
    );

    res.status(201).json({ 
      message: 'Coaching application submitted successfully',
      application_id: result.rows[0].id
    });
  } catch (error) {
    console.error('Coaching application error:', error);
    res.status(500).json({ error: 'Failed to submit application' });
  }
});

// Stripe webhook handler
app.post('/api/webhooks/stripe', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed':
        const session = event.data.object;
        const userId = session.metadata.user_id;
        const tier = session.metadata.tier;
        
        if (tier === 'teacher_intensive') {
          // One-time payment for 90-day intensive
          await pool.query(
            `UPDATE users SET 
             tier = 'teacher', 
             subscription_status = 'active',
             subscription_start_date = NOW(),
             subscription_end_date = NOW() + INTERVAL '90 days'
             WHERE id = $1`,
            [userId]
          );
        } else {
          // Recurring subscription
          await pool.query(
            `UPDATE users SET 
             tier = $1, 
             subscription_status = 'active',
             subscription_start_date = NOW(),
             stripe_subscription_id = $2
             WHERE id = $3`,
            [PRICING_CONFIG[tier].tier, session.subscription, userId]
          );
        }
        break;

      case 'invoice.payment_succeeded':
        // Handle successful recurring payment
        break;

      case 'customer.subscription.deleted':
        const subscription = event.data.object;
        await pool.query(
          `UPDATE users SET 
           tier = 'novice', 
           subscription_status = 'cancelled',
           stripe_subscription_id = NULL
           WHERE stripe_subscription_id = $1`,
          [subscription.id]
        );
        break;

      default:
        console.log(`Unhandled event type ${event.type}`);
    }

    res.json({ received: true });
  } catch (error) {
    console.error('Webhook handling error:', error);
    res.status(500).json({ error: 'Webhook handling failed' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    zevgpt_enabled: !!process.env.OPENAI_API_KEY
  });
});

// Initialize and start server
const startServer = async () => {
  await initDB();
  app.listen(port, () => {
    console.log(`🚀 Ayeka Backend Server running on port ${port}`);
    console.log(`📊 Health check: http://localhost:${port}/health`);
    console.log(`💳 Webhook endpoint: http://localhost:${port}/api/webhooks/stripe`);
    console.log(`🤖 ZevGPT: ${process.env.OPENAI_API_KEY ? 'Enabled' : 'Disabled - Set OPENAI_API_KEY'}`);
  });
};

startServer().catch(console.error);