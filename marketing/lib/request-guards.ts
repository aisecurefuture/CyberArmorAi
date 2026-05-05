import { NextRequest, NextResponse } from "next/server";

type RateLimitRecord = {
  count: number;
  resetAt: number;
};

const rateLimitStore = new Map<string, RateLimitRecord>();

const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 5;

function normalizeHost(value: string | null | undefined): string | null {
  if (!value) {
    return null;
  }

  return value.split(":")[0].trim().toLowerCase() || null;
}

function buildAllowedHosts(): Set<string> {
  const hosts = [
    process.env.MARKETING_DOMAIN,
    process.env.WWW_MARKETING_DOMAIN,
    process.env.SUPPORT_DOMAIN,
  ]
    .map(normalizeHost)
    .filter((value): value is string => Boolean(value));

  if (process.env.NODE_ENV !== "production") {
    hosts.push("localhost", "127.0.0.1");
  }

  return new Set(hosts);
}

function extractSourceHost(req: NextRequest): string | null {
  const origin = req.headers.get("origin");
  if (origin) {
    try {
      return normalizeHost(new URL(origin).host);
    } catch {
      return null;
    }
  }

  const referer = req.headers.get("referer");
  if (referer) {
    try {
      return normalizeHost(new URL(referer).host);
    } catch {
      return null;
    }
  }

  return null;
}

function extractClientIp(req: NextRequest): string {
  const forwardedFor = req.headers.get("x-forwarded-for");
  if (forwardedFor) {
    const first = forwardedFor.split(",")[0]?.trim();
    if (first) {
      return first;
    }
  }

  const realIp = req.headers.get("x-real-ip")?.trim();
  if (realIp) {
    return realIp;
  }

  return "unknown";
}

function cleanupExpiredEntries(now: number) {
  for (const [key, record] of rateLimitStore.entries()) {
    if (record.resetAt <= now) {
      rateLimitStore.delete(key);
    }
  }
}

export function enforceAllowedOrigin(req: NextRequest): NextResponse | null {
  const allowedHosts = buildAllowedHosts();
  const sourceHost = extractSourceHost(req);

  if (!sourceHost || !allowedHosts.has(sourceHost)) {
    return NextResponse.json({ error: "Invalid request origin" }, { status: 403 });
  }

  return null;
}

export function enforceRateLimit(req: NextRequest, scope: string): NextResponse | null {
  const now = Date.now();
  cleanupExpiredEntries(now);

  const ip = extractClientIp(req);
  const key = `${scope}:${ip}`;
  const current = rateLimitStore.get(key);

  if (!current || current.resetAt <= now) {
    rateLimitStore.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return null;
  }

  if (current.count >= RATE_LIMIT_MAX_REQUESTS) {
    const retryAfterSeconds = Math.max(1, Math.ceil((current.resetAt - now) / 1000));
    return NextResponse.json(
      { error: "Too many requests. Please try again in a few minutes." },
      {
        status: 429,
        headers: {
          "Retry-After": String(retryAfterSeconds),
        },
      },
    );
  }

  current.count += 1;
  rateLimitStore.set(key, current);
  return null;
}
