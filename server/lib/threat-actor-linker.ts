/**
 * Auto-links analysis results to canonical threat actor records.
 * Called after analysis completes — wrapped in try-catch by the caller
 * so failures never break the analysis pipeline.
 */
import crypto from 'crypto';
import logger from './logger.js';

interface ThreatActorData {
  name: string | null;
  aliases: string[];
  motivation: string | null;
  attribution_confidence: string | null;
  intrusion_set?: string | null;
  campaign_name?: string | null;
  malware_families?: string[];
}

interface AnalysisResultLike {
  threat_actor: ThreatActorData;
}

interface ThreatActorRow {
  id: string;
  name: string;
  aliases: string;
  motivation: string | null;
  attribution_confidence: string | null;
  intrusion_set: string | null;
  campaign_name: string | null;
  malware_families: string;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function autoLinkThreatActor(db: any, sessionId: string, result: AnalysisResultLike, teamId: string, userId: string): Promise<void> {
  const actor = result.threat_actor;
  const hasAttribution = actor?.name && actor.name.trim();

  // If no attribution, link to the team's "Unattributed" placeholder
  if (!hasAttribution) {
    await linkToUnattributed(db, sessionId, teamId, userId);
    return;
  }

  const name = actor.name!.trim();
  const nameLower = name.toLowerCase();
  const now = Date.now();

  // Check if this session is already linked to any actor
  const existingLink = (await db.prepare(
    'SELECT threat_actor_id FROM session_threat_actors WHERE session_id = ?'
  ).get(sessionId)) as { threat_actor_id: string } | undefined;

  if (existingLink) {
    logger.debug({ sessionId, actorId: existingLink.threat_actor_id }, 'Session already linked to a threat actor');
    return;
  }

  // Try to find an existing canonical actor by exact name match (case-insensitive)
  let matched: ThreatActorRow | undefined = (await db.prepare(
    'SELECT * FROM threat_actors WHERE LOWER(name) = ? AND team_id = ?'
  ).get(nameLower, teamId)) as ThreatActorRow | undefined;

  // If no exact name match, check aliases across all team actors
  if (!matched) {
    const allActors = (await db.prepare(
      'SELECT * FROM threat_actors WHERE team_id = ?'
    ).all(teamId)) as ThreatActorRow[];

    for (const a of allActors) {
      try {
        const aliases: string[] = JSON.parse(a.aliases || '[]');
        if (aliases.some((alias: string) => alias.toLowerCase() === nameLower)) {
          matched = a;
          break;
        }
      } catch { /* invalid JSON — skip */ }
    }
  }

  if (matched) {
    // Link session to existing actor
    await db.prepare(
      'INSERT INTO session_threat_actors (session_id, threat_actor_id, link_type, linked_at, linked_by) VALUES (?, ?, ?, ?, ?) ON CONFLICT (session_id, threat_actor_id) DO NOTHING'
    ).run(sessionId, matched.id, 'auto', now, userId);

    // Enrich canonical record with new optional fields if they were empty
    let updated = false;
    const updates: string[] = [];
    const params: unknown[] = [];

    if (actor.intrusion_set && !matched.intrusion_set) {
      updates.push('intrusion_set = ?');
      params.push(actor.intrusion_set);
      updated = true;
    }
    if (actor.campaign_name && !matched.campaign_name) {
      updates.push('campaign_name = ?');
      params.push(actor.campaign_name);
      updated = true;
    }
    if (actor.malware_families && actor.malware_families.length > 0) {
      try {
        const existing: string[] = JSON.parse(matched.malware_families || '[]');
        const merged = [...new Set([...existing, ...actor.malware_families])];
        if (merged.length > existing.length) {
          updates.push('malware_families = ?');
          params.push(JSON.stringify(merged));
          updated = true;
        }
      } catch { /* invalid JSON — skip enrichment */ }
    }

    // Merge new aliases
    if (actor.aliases && actor.aliases.length > 0) {
      try {
        const existing: string[] = JSON.parse(matched.aliases || '[]');
        const existingLower = new Set(existing.map((a: string) => a.toLowerCase()));
        const newAliases = actor.aliases.filter((a: string) => !existingLower.has(a.toLowerCase()) && a.toLowerCase() !== matched!.name.toLowerCase());
        if (newAliases.length > 0) {
          updates.push('aliases = ?');
          params.push(JSON.stringify([...existing, ...newAliases]));
          updated = true;
        }
      } catch { /* invalid JSON — skip */ }
    }

    if (updated) {
      updates.push('updated_at = ?');
      params.push(now);
      params.push(matched.id);
      await db.prepare(`UPDATE threat_actors SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    }

    logger.info({ sessionId, actorId: matched.id, actorName: matched.name }, 'Session auto-linked to existing threat actor');
  } else {
    // Create new canonical actor record
    const actorId = crypto.randomUUID();
    await db.prepare(`
      INSERT INTO threat_actors (id, name, aliases, motivation, attribution_confidence, intrusion_set, campaign_name, malware_families, description, team_id, created_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      actorId,
      name,
      JSON.stringify(actor.aliases || []),
      actor.motivation || null,
      actor.attribution_confidence || null,
      actor.intrusion_set || null,
      actor.campaign_name || null,
      JSON.stringify(actor.malware_families || []),
      '',
      teamId,
      userId,
      now,
      now,
    );

    // Link session to new actor
    await db.prepare(
      'INSERT INTO session_threat_actors (session_id, threat_actor_id, link_type, linked_at, linked_by) VALUES (?, ?, ?, ?, ?)'
    ).run(sessionId, actorId, 'auto', now, userId);

    logger.info({ sessionId, actorId, actorName: name }, 'Created new threat actor and auto-linked session');
  }
}

/** Find-or-create the team-scoped "Unattributed" placeholder and link the session to it. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function linkToUnattributed(db: any, sessionId: string, teamId: string, userId: string): Promise<void> {
  const now = Date.now();

  // Already linked?
  const existingLink = (await db.prepare(
    'SELECT threat_actor_id FROM session_threat_actors WHERE session_id = ?'
  ).get(sessionId)) as { threat_actor_id: string } | undefined;
  if (existingLink) return;

  // Find the team's "Unattributed" actor
  let placeholder = (await db.prepare(
    "SELECT id FROM threat_actors WHERE name = 'Unattributed' AND team_id = ?"
  ).get(teamId)) as { id: string } | undefined;

  if (!placeholder) {
    const id = crypto.randomUUID();
    await db.prepare(`
      INSERT INTO threat_actors (id, name, aliases, motivation, attribution_confidence, intrusion_set, campaign_name, malware_families, description, team_id, created_by, created_at, updated_at)
      VALUES (?, 'Unattributed', '[]', NULL, NULL, NULL, NULL, '[]', 'Sessions where no specific threat actor could be attributed.', ?, ?, ?, ?)
    `).run(id, teamId, userId, now, now);
    placeholder = { id };
    logger.info({ teamId }, 'Created "Unattributed" placeholder actor for team');
  }

  await db.prepare(
    'INSERT INTO session_threat_actors (session_id, threat_actor_id, link_type, linked_at, linked_by) VALUES (?, ?, ?, ?, ?) ON CONFLICT (session_id, threat_actor_id) DO NOTHING'
  ).run(sessionId, placeholder.id, 'auto', now, userId);

  logger.debug({ sessionId }, 'Session auto-linked to Unattributed placeholder');
}
