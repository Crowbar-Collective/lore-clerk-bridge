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
  // A session is completed once. Without this, anyone who learns a session code could
  // overwrite a finished login with a token minted for their own Clerk account, and the
  // CLI that started the session would come back holding the attacker's identity rather
  // than the user's - authenticated as the wrong person, with the wrong grants.
  if (record.status === "complete") return false;
  record.status = "complete";
  record.userToken = userToken;
  return true;
}

/**
 * Drops a session once its token has been handed to the client that started it.
 *
 * <p>The token is the entire value of a session, so leaving it readable for the rest of
 * the five-minute TTL means anyone who later learns the code - from browser history, a
 * proxy log, a shared screen - can still collect it. Delivering it exactly once is the
 * same trade an OAuth authorization code makes: a client that loses the response starts
 * a new login rather than polling again.
 */
export function deleteSession(sessionCode: string): void {
  sessions.delete(sessionCode);
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
