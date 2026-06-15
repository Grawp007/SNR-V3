/**
 * Express middleware for authentication, role-based access control, and team scoping.
 */

import type { Request, Response, NextFunction } from 'express';
import { verifyToken, isTokenRevoked } from '../lib/auth-utils.js';
import { getDb } from '../db/database.js';
import logger from '../lib/logger.js';

export interface AuthUser {
  id: string;
  email: string;
  displayName: string;
  role: 'admin' | 'analyst' | 'viewer';
  teamIds: string[];
}

export interface AuthenticatedRequest extends Request {
  user: AuthUser;
  teamId: string;
}

/**
 * Verify JWT from Authorization header and attach user to request.
 * Returns 401 if token is missing, invalid, or user is disabled.
 */
export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  const token = authHeader.slice(7);
  let payload;
  try {
    payload = verifyToken(token);
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
    return;
  }

  if (payload.type !== 'access') {
    res.status(401).json({ error: 'Invalid token type' });
    return;
  }

  try {
    // Check token revocation blacklist (indexed lookup)
    if (payload.jti && (await isTokenRevoked(payload.jti))) {
      res.status(401).json({ error: 'Token has been revoked' });
      return;
    }

    const db = getDb();
    const user = (await db.prepare(
      'SELECT id, email, display_name, role, disabled FROM users WHERE id = ?'
    ).get(payload.sub)) as { id: string; email: string; display_name: string; role: string; disabled: number } | undefined;

    if (!user || user.disabled) {
      res.status(401).json({ error: 'Account not found or disabled' });
      return;
    }

    // Load team memberships
    const teams = (await db.prepare(
      'SELECT team_id FROM team_members WHERE user_id = ?'
    ).all(user.id)) as Array<{ team_id: string }>;

    (req as AuthenticatedRequest).user = {
      id: user.id,
      email: user.email,
      displayName: user.display_name,
      role: user.role as AuthUser['role'],
      teamIds: teams.map(t => t.team_id),
    };

    next();
  } catch (err) {
    logger.error({ err }, 'Auth middleware database error');
    res.status(503).json({ error: 'Service temporarily unavailable' });
  }
}

/**
 * Factory: require the authenticated user to have one of the specified roles.
 * Must be used AFTER requireAuth.
 */
export function requireRole(...roles: Array<'admin' | 'analyst' | 'viewer'>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const authReq = req as AuthenticatedRequest;
    if (!authReq.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }
    if (!roles.includes(authReq.user.role)) {
      res.status(403).json({ error: `Requires role: ${roles.join(' or ')}` });
      return;
    }
    next();
  };
}

/**
 * Resolve team context from X-Team-Id header.
 * Admins can access any team. Other users must be a member.
 * Must be used AFTER requireAuth.
 */
export function requireTeamMember(req: Request, res: Response, next: NextFunction): void {
  const authReq = req as AuthenticatedRequest;
  if (!authReq.user) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  const teamId = req.headers['x-team-id'] as string | undefined;
  if (!teamId) {
    // If user belongs to exactly one team, auto-select it
    if (authReq.user.teamIds.length === 1) {
      authReq.teamId = authReq.user.teamIds[0];
      next();
      return;
    }
    // Admins with no team header — allow but set teamId to empty (they can query globally)
    if (authReq.user.role === 'admin') {
      authReq.teamId = '';
      next();
      return;
    }
    res.status(400).json({ error: 'X-Team-Id header required' });
    return;
  }

  // Admins can access any team
  if (authReq.user.role === 'admin') {
    authReq.teamId = teamId;
    next();
    return;
  }

  // Regular users must be a member
  if (!authReq.user.teamIds.includes(teamId)) {
    res.status(403).json({ error: 'Not a member of this team' });
    return;
  }

  authReq.teamId = teamId;
  next();
}
