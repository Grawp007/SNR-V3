import { Router } from 'express';
import { getDb, appendAuditLog } from '../db/database.js';
import { hashPassword, verifyPassword, signAccessToken, signRefreshToken, verifyToken, validatePasswordStrength, revokeToken, isTokenRevoked } from '../lib/auth-utils.js';
import { requireAuth, type AuthenticatedRequest } from '../middleware/auth.js';
import logger from '../lib/logger.js';

const router = Router();

// Fake bcrypt hash — used for constant-time response when user not found (timing attack prevention)
const FAKE_HASH = '$2a$12$0000000000000000000000uGWzoFYMmgLz6xBnP2y5lF1u4hOqiS';

// Account lockout settings
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

// POST /api/auth/login — no auth required
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      res.status(400).json({ error: 'Email and password are required' });
      return;
    }

    const db = getDb();
    const user = (await db.prepare(
      'SELECT id, email, password_hash, display_name, role, disabled, failed_login_attempts, locked_until FROM users WHERE LOWER(email) = LOWER(?)'
    ).get(email.trim().toLowerCase())) as {
      id: string; email: string; password_hash: string; display_name: string; role: string;
      disabled: number; failed_login_attempts: number; locked_until: number;
    } | undefined;

    // Check account lockout (before password verification to maintain timing consistency)
    if (user?.locked_until && Date.now() < user.locked_until) {
      const minutesLeft = Math.ceil((user.locked_until - Date.now()) / 60000);
      // Still run password verification for timing consistency
      await verifyPassword(password, user.password_hash);
      appendAuditLog({ analyst_name: email, action: 'login_locked', details: `Account locked, ${minutesLeft}m remaining. IP: ${req.ip}` });
      res.status(401).json({ error: `Account temporarily locked. Try again in ${minutesLeft} minutes.` });
      return;
    }

    if (user?.disabled) {
      // Still run password verification for timing consistency
      await verifyPassword(password, user.password_hash);
      res.status(401).json({ error: 'Account is disabled. Contact an administrator.' });
      return;
    }

    // Constant-time password verification — always runs bcrypt even if user not found
    const valid = await verifyPassword(password, user?.password_hash ?? FAKE_HASH);
    if (!user || !valid) {
      // Track failed attempts
      if (user) {
        const newAttempts = (user.failed_login_attempts || 0) + 1;
        if (newAttempts >= MAX_FAILED_ATTEMPTS) {
          const lockedUntil = Date.now() + LOCKOUT_DURATION_MS;
          await db.prepare('UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?')
            .run(newAttempts, lockedUntil, user.id);
          appendAuditLog({ analyst_name: user.email, user_id: user.id, action: 'account_locked', details: `Locked after ${newAttempts} failed attempts. IP: ${req.ip}` });
        } else {
          await db.prepare('UPDATE users SET failed_login_attempts = ? WHERE id = ?')
            .run(newAttempts, user.id);
        }
        appendAuditLog({ analyst_name: user.email, user_id: user.id, action: 'login_failed', details: `Attempt ${newAttempts}. IP: ${req.ip}` });
      }
      res.status(401).json({ error: 'Invalid email or password' });
      return;
    }

    // Successful login — reset failed attempts
    await db.prepare('UPDATE users SET last_login_at = ?, failed_login_attempts = 0, locked_until = 0 WHERE id = ?')
      .run(Date.now(), user.id);

    // Load teams
    const teams = (await db.prepare(`
      SELECT t.id, t.name, tm.role as team_role
      FROM teams t JOIN team_members tm ON t.id = tm.team_id
      WHERE tm.user_id = ?
    `).all(user.id)) as Array<{ id: string; name: string; team_role: string }>;

    const token = signAccessToken({ id: user.id, email: user.email, role: user.role });
    const refreshToken = signRefreshToken({ id: user.id, email: user.email, role: user.role });

    appendAuditLog({ analyst_name: user.display_name, user_id: user.id, action: 'login', details: `IP: ${req.ip}` });

    res.json({
      token,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        displayName: user.display_name,
        role: user.role,
      },
      teams: teams.map(t => ({ id: t.id, name: t.name, role: t.team_role })),
    });
  } catch (err) {
    logger.error('Login error:', err instanceof Error ? err.message : 'Unknown');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/refresh — no auth required, uses refresh token
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      res.status(400).json({ error: 'Refresh token required' });
      return;
    }

    let payload;
    try {
      payload = verifyToken(refreshToken);
    } catch {
      res.status(401).json({ error: 'Invalid or expired refresh token' });
      return;
    }

    if (payload.type !== 'refresh') {
      res.status(401).json({ error: 'Invalid token type' });
      return;
    }

    // Check if refresh token has been revoked
    if (payload.jti && (await isTokenRevoked(payload.jti))) {
      res.status(401).json({ error: 'Token has been revoked' });
      return;
    }

    const db = getDb();
    const user = (await db.prepare('SELECT id, email, role, disabled FROM users WHERE id = ?').get(payload.sub)) as {
      id: string; email: string; role: string; disabled: number;
    } | undefined;

    if (!user || user.disabled) {
      res.status(401).json({ error: 'Account not found or disabled' });
      return;
    }

    // Revoke the consumed refresh token to prevent reuse
    if (payload.jti && payload.exp) {
      await revokeToken(payload.jti, payload.exp * 1000);
    }

    const newToken = signAccessToken({ id: user.id, email: user.email, role: user.role });
    const newRefresh = signRefreshToken({ id: user.id, email: user.email, role: user.role });

    res.json({ token: newToken, refreshToken: newRefresh });
  } catch (err) {
    logger.error('Token refresh error:', err instanceof Error ? err.message : 'Unknown');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/auth/me — requires auth
router.get('/me', requireAuth, async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();

  const teams = (await db.prepare(`
    SELECT t.id, t.name, tm.role as team_role
    FROM teams t JOIN team_members tm ON t.id = tm.team_id
    WHERE tm.user_id = ?
  `).all(authReq.user.id)) as Array<{ id: string; name: string; team_role: string }>;

  res.json({
    user: {
      id: authReq.user.id,
      email: authReq.user.email,
      displayName: authReq.user.displayName,
      role: authReq.user.role,
    },
    teams: teams.map(t => ({ id: t.id, name: t.name, role: t.team_role })),
  });
});

// PATCH /api/auth/me/password — requires auth
router.patch('/me/password', requireAuth, async (req, res) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      res.status(400).json({ error: 'Current and new passwords are required' });
      return;
    }

    // Enforce password complexity
    const strength = validatePasswordStrength(newPassword);
    if (!strength.valid) {
      res.status(400).json({ error: strength.errors.join('. ') });
      return;
    }

    const db = getDb();
    const user = (await db.prepare('SELECT password_hash FROM users WHERE id = ?').get(authReq.user.id)) as { password_hash: string };

    const valid = await verifyPassword(currentPassword, user.password_hash);
    if (!valid) {
      res.status(401).json({ error: 'Current password is incorrect' });
      return;
    }

    const newHash = await hashPassword(newPassword);
    const now = Date.now();
    await db.prepare('UPDATE users SET password_hash = ?, updated_at = ?, password_changed_at = ? WHERE id = ?').run(newHash, now, now, authReq.user.id);

    // Revoke the current token to force re-login with new password
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      try {
        const currentPayload = verifyToken(authHeader.slice(7));
        if (currentPayload.jti && currentPayload.exp) {
          await revokeToken(currentPayload.jti, currentPayload.exp * 1000);
        }
      } catch { /* token already expired — no action needed */ }
    }

    appendAuditLog({ analyst_name: authReq.user.displayName, user_id: authReq.user.id, action: 'password_changed', details: 'Self-service password change' });

    res.json({ ok: true, message: 'Password changed. Please log in again.' });
  } catch (err) {
    logger.error('Password change error:', err instanceof Error ? err.message : 'Unknown');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/logout — requires auth, revokes current token
router.post('/logout', requireAuth, async (req, res) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      try {
        const payload = verifyToken(authHeader.slice(7));
        if (payload.jti && payload.exp) {
          await revokeToken(payload.jti, payload.exp * 1000);
        }
      } catch { /* token already expired — harmless */ }
    }

    appendAuditLog({ analyst_name: authReq.user.displayName, user_id: authReq.user.id, action: 'logout', details: `IP: ${req.ip}` });

    res.json({ ok: true });
  } catch (err) {
    logger.error('Logout error:', err instanceof Error ? err.message : 'Unknown');
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
