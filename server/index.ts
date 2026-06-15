import { config } from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { getDb, initDb, bootstrapAdmin, closeDb } from './db/database.js';
import { pingDb } from './db/client.js';
import { requireAuth, requireTeamMember } from './middleware/auth.js';
import { cleanupRevokedTokens, initAuthSecret } from './lib/auth-utils.js';
import { readSecret } from './lib/secrets.js';
import { startBackupScheduler } from './lib/backup.js';
import { registry } from './lib/metrics.js';
import logger, { requestLogger } from './lib/logger.js';
import authRouter from './routes/auth.js';
import usersRouter from './routes/users.js';
import teamsRouter from './routes/teams.js';
import analyzeRouter from './routes/analyze.js';
import sessionsRouter from './routes/sessions.js';
import settingsRouter from './routes/settings.js';
import analyticsRouter from './routes/analytics.js';
import threatActorsRouter from './routes/threat-actors.js';
import searchRouter from './routes/search.js';

// Resolve .env relative to this file's location (server/ → project root)
// Using import.meta.url ensures this works regardless of the working directory.
// override:false → real environment variables take precedence over .env, which
// is the correct 12-factor behavior for containers/orchestrators (.env is only
// a fallback for local dev).
const __dirname = path.dirname(fileURLToPath(import.meta.url));
config({ override: false, path: path.resolve(__dirname, '../.env') });

const app = express();
const PORT = parseInt(process.env.PORT ?? '3001', 10);
const isProd = process.env.NODE_ENV === 'production';
// Bind 0.0.0.0 in production (containers/remote) but stay loopback-only in dev.
const HOST = process.env.HOST ?? (isProd ? '0.0.0.0' : '127.0.0.1');

// Trust the reverse proxy in front of us so express-rate-limit and req.ip use
// the real client IP from X-Forwarded-For. TRUST_PROXY accepts a hop count
// (e.g. "1") or a boolean; defaults to 1 hop in prod, off in dev.
const trustProxy = process.env.TRUST_PROXY ?? (isProd ? '1' : '');
if (trustProxy) {
  const n = parseInt(trustProxy, 10);
  app.set('trust proxy', Number.isNaN(n) ? trustProxy : n);
}

// Security headers
app.use(helmet({
  contentSecurityPolicy: process.env.NODE_ENV === 'production'
    ? {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:'],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          frameAncestors: ["'none'"],
        },
      }
    : false, // Managed by Vite in dev
  hsts: { maxAge: 31536000, includeSubDomains: true },
  frameguard: { action: 'deny' },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

// CORS — production requires ALLOWED_ORIGINS env var; dev allows Vite dev server
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? (process.env.ALLOWED_ORIGINS
        ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean)
        : false)
    : ['http://localhost:5173', 'http://127.0.0.1:5173'],
  credentials: true,
}));

// Rate limiting for API endpoints
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

// Strict rate limiting for auth endpoints (brute force protection)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,                    // 5 attempts per window
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
});

// Password change rate limiting
const passwordLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,                    // 5 attempts per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many password change attempts. Please try again later.' },
});

app.use('/api/', apiLimiter);

// Body parsing (not for file upload routes — multer handles those)
app.use(express.json({ limit: '12mb' }));
app.use(express.urlencoded({ extended: false }));

// Request logging
app.use(requestLogger);

// Database is initialized asynchronously in start() before the server listens.

// ── Auth routes (no auth middleware — login/refresh are public) ───────────
// Apply strict rate limiting to login/refresh to prevent brute force
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/refresh', authLimiter);
app.use('/api/auth/me/password', passwordLimiter);
app.use('/api/auth', authRouter);

// ── Protected routes — require authentication ────────────────────────────
app.use('/api/users', requireAuth, usersRouter);
app.use('/api/teams', requireAuth, teamsRouter);
app.use('/api/sessions', requireAuth, requireTeamMember, sessionsRouter);
app.use('/api/analyze', requireAuth, requireTeamMember, analyzeRouter);
app.use('/api/settings', requireAuth, requireTeamMember, settingsRouter);
app.use('/api/analytics', requireAuth, requireTeamMember, analyticsRouter);
app.use('/api/threat-actors', requireAuth, requireTeamMember, threatActorsRouter);
app.use('/api/search', requireAuth, requireTeamMember, searchRouter);

// Health check (no auth — used for monitoring)
const startedAt = Date.now();
app.get('/api/health', async (_req, res) => {
  try {
    await pingDb();
    res.json({
      status: 'ok',
      uptime: Math.floor((Date.now() - startedAt) / 1000),
      version: '3.0.0',
      llm: readSecret('ANTHROPIC_API_KEY') ? 'configured' : 'not_configured',
    });
  } catch {
    res.status(503).json({ status: 'degraded', error: 'database unavailable' });
  }
});

// Readiness probe (DB writable + migrations applied)
app.get('/api/ready', async (_req, res) => {
  try {
    const db = getDb();
    // Verify read + write capability
    await db.exec('CREATE TABLE IF NOT EXISTS _health_check (id INTEGER PRIMARY KEY)');
    await db.prepare('INSERT INTO _health_check (id) VALUES (1) ON CONFLICT (id) DO NOTHING').run();
    await db.prepare('DELETE FROM _health_check WHERE id = 1').run();
    res.json({ status: 'ready' });
  } catch {
    res.status(503).json({ status: 'not_ready', error: 'database not writable' });
  }
});

// Prometheus metrics (no /api prefix → not rate-limited). Optionally gated by a
// bearer token for scrapers via METRICS_TOKEN.
app.get('/metrics', async (req, res) => {
  const token = process.env.METRICS_TOKEN;
  if (token && req.headers.authorization !== `Bearer ${token}`) {
    res.status(401).end();
    return;
  }
  res.set('Content-Type', registry.contentType);
  res.end(await registry.metrics());
});

// Serve built frontend in production (Vite outputs to <root>/dist; this file
// lives at <root>/server, so the build is one level up).
if (isProd) {
  const distPath = path.resolve(__dirname, '../dist');
  app.use(express.static(distPath));
  app.get('*', (_req, res) => {
    res.sendFile(path.join(distPath, 'index.html'));
  });
}

/**
 * Fail fast on misconfiguration in production so the operator gets a clear
 * error at boot instead of subtle runtime failures.
 */
function validateProdConfig(): void {
  if (!isProd) return;
  const errors: string[] = [];
  if (!readSecret('JWT_SECRET')) errors.push('JWT_SECRET (or JWT_SECRET_FILE) is required in production.');
  if (!process.env.ALLOWED_ORIGINS?.trim()) errors.push('ALLOWED_ORIGINS is required in production (comma-separated origins for CORS).');
  const llmConfigured = !!readSecret('ANTHROPIC_API_KEY') || process.env.LLM_PROVIDER === 'openai-compatible';
  if (!llmConfigured) errors.push('An LLM provider must be configured (ANTHROPIC_API_KEY / _FILE, or an OpenAI-compatible provider in settings).');

  if (errors.length > 0) {
    logger.fatal('Invalid production configuration:');
    for (const e of errors) logger.fatal(`  - ${e}`);
    process.exit(1);
  }
}

// ── Start server ─────────────────────────────────────────────────────────
async function start() {
  // Validate critical config before doing anything else (prod only)
  validateProdConfig();

  // Initialize the database (apply migrations, seed settings) before serving.
  await initDb();

  // Resolve and cache the JWT signing secret (keeps token sign/verify synchronous).
  await initAuthSecret();

  // Bootstrap admin account on first run (idempotent)
  await bootstrapAdmin();

  const server = app.listen(PORT, HOST, () => {
    logger.info(`SNR Server running at http://${HOST}:${PORT}`);
    logger.info(`LLM Provider: ${readSecret('ANTHROPIC_API_KEY') ? '✓ Configured' : '✗ NOT configured — add ANTHROPIC_API_KEY to .env'}`);
  });

  // Periodic cleanup of revoked tokens (every hour)
  const cleanupInterval = setInterval(() => {
    cleanupRevokedTokens().catch((err) => {
      logger.error({ err }, 'Failed to cleanup revoked tokens');
    });
  }, 60 * 60 * 1000);

  // Scheduled database backups (consistent VACUUM INTO snapshots + retention)
  const stopBackups = startBackupScheduler();

  // Graceful shutdown
  const shutdown = (signal: string) => {
    logger.info({ signal }, 'Received shutdown signal, closing gracefully…');
    clearInterval(cleanupInterval);
    stopBackups();
    server.close(async () => {
      logger.info('HTTP server closed');
      try {
        await closeDb();
        logger.info('Database connection pool closed');
      } catch { /* DB may already be closed */ }
      process.exit(0);
    });
    // Force exit after 10s if graceful shutdown stalls
    setTimeout(() => {
      logger.warn('Graceful shutdown timed out, forcing exit');
      process.exit(1);
    }, 10_000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

start().catch((err) => {
  logger.fatal({ err }, 'Failed to start server');
  process.exit(1);
});

export default app;
