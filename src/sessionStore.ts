import { randomBytes } from "node:crypto";

export interface IssuedUserToken {
  userToken: string;
  expiresAt: number; // epoch seconds
  userId: string;
  userName: string;
}

interface SessionRecord {
  clientState: string;
  status: "pending" | "complete";
  userToken?: IssuedUserToken;
  createdAt: number; // epoch ms
}

const SESSION_TTL_MS = 5 * 60 * 1000;

// StartAuthSession is necessarily unauthenticated (it runs before the user has logged in),
// so anyone who can reach the gRPC endpoint can create sessions. Without a ceiling that is
// an unbounded allocation driven by an anonymous caller. Sessions are tiny and expire in
// five minutes, so this only has to be large enough that real logins never reach it while
// still bounding the damage; evicting oldest-first keeps a flood from locking out
// legitimate users, since a flood's own entries are the first to go.
const MAX_SESSIONS = Number(process.env.MAX_SESSIONS ?? 10_000);
const sessions = new Map<string, SessionRecord>();

export function createSession(clientState: string): string {
  if (sessions.size >= MAX_SESSIONS) {
    sweepExpiredSessions();
    // Map preserves insertion order, so the first remaining key is the oldest.
    while (sessions.size >= MAX_SESSIONS) {
      const oldest = sessions.keys().next();
      if (oldest.done) break;
      sessions.delete(oldest.value);
    }
    console.warn(`Session store at capacity (${MAX_SESSIONS}); evicting oldest entries`);
  }

  const sessionCode = randomBytes(24).toString("base64url");
  sessions.set(sessionCode, {
    clientState,
    status: "pending",
    createdAt: Date.now(),
  });
  return sessionCode;
}

export function getSession(sessionCode: string): SessionRecord | undefined {
  const record = sessions.get(sessionCode);
  if (record && Date.now() - record.createdAt > SESSION_TTL_MS) {
    sessions.delete(sessionCode);
    return undefined;
  }
  return record;
}

export function completeSession(sessionCode: string, userToken: IssuedUserToken): boolean {
  const record = getSession(sessionCode);
  if (!record) return false;
  record.status = "complete";
  record.userToken = userToken;
  return true;
}

function sweepExpiredSessions(): void {
  const now = Date.now();
  for (const [code, record] of sessions) {
    if (now - record.createdAt > SESSION_TTL_MS) {
      sessions.delete(code);
    }
  }
}

setInterval(sweepExpiredSessions, 60 * 1000).unref();
