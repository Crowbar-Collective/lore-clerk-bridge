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
const sessions = new Map<string, SessionRecord>();

export function createSession(clientState: string): string {
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
