// Fixed-window rate limiting, in-process and dependency-free.
//
// In the app rather than at the edge on purpose: the two endpoints worth limiting are
// reachable by anyone, and one of them spends a third-party API quota on every call, so
// the protection should travel with the service instead of depending on each operator
// reproducing an edge config. An edge limiter in front of this is still worth having;
// they compose fine.

interface Window {
  count: number;
  resetAt: number;
}

export interface RateLimiter {
  /** Records a hit. Returns false when the caller is over its limit. */
  check(key: string): boolean;
  /** Seconds until the current window rolls over, for Retry-After. */
  retryAfter(key: string): number;
}

export function createRateLimiter(limit: number, windowMs: number, maxKeys = 10_000): RateLimiter {
  const windows = new Map<string, Window>();

  // The limiter must not become the exhaustion it prevents: an attacker rotating source
  // addresses would otherwise grow this map without bound. Expired entries go first, and
  // only if that frees nothing does it evict live ones (oldest first, since Map preserves
  // insertion order).
  const evictIfFull = (now: number): void => {
    if (windows.size < maxKeys) return;
    for (const [key, w] of windows) {
      if (w.resetAt <= now) windows.delete(key);
    }
    while (windows.size >= maxKeys) {
      const oldest = windows.keys().next();
      if (oldest.done) break;
      windows.delete(oldest.value);
    }
  };

  return {
    check(key: string): boolean {
      const now = Date.now();
      let w = windows.get(key);
      if (!w || w.resetAt <= now) {
        evictIfFull(now);
        w = { count: 0, resetAt: now + windowMs };
        windows.set(key, w);
      }
      w.count += 1;
      return w.count <= limit;
    },
    retryAfter(key: string): number {
      const w = windows.get(key);
      if (!w) return 0;
      return Math.max(0, Math.ceil((w.resetAt - Date.now()) / 1000));
    },
  };
}

export const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX ?? 30);
export const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_SECONDS ?? 60) * 1000;

/**
 * True when an address belongs to a range only reachable from inside the deployment,
 * which is what makes a forwarded client address trustworthy: this service is meant to
 * sit behind a proxy, so a request arriving from a private peer came through it, while
 * one arriving from a public peer did not and may claim whatever it likes.
 */
export function isTrustedPeer(address: string): boolean {
  const ip = address.replace(/^::ffff:/, "");
  return (
    ip === "127.0.0.1" ||
    ip === "::1" ||
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2[0-9]|3[01])\./.test(ip) ||
    /^f[cd]/i.test(ip) // fc00::/7 unique local
  );
}

/** Extracts the peer address from a gRPC `getPeer()` string such as `ipv4:10.0.0.5:53124`. */
export function peerAddress(peer: string): string {
  const withoutScheme = peer.replace(/^ipv[46]:/, "");
  const bracketed = /^\[(.+)\]:\d+$/.exec(withoutScheme);
  if (bracketed) return bracketed[1];
  const lastColon = withoutScheme.lastIndexOf(":");
  return lastColon === -1 ? withoutScheme : withoutScheme.slice(0, lastColon);
}
