import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

function normalizeHost(hostHeader: string | null): string {
  return (hostHeader ?? "").split(":")[0].toLowerCase();
}

export function proxy(request: NextRequest) {
  const host = normalizeHost(request.headers.get("host"));
  const supportDomain = (process.env.SUPPORT_DOMAIN ?? "support.cyberarmor.ai").toLowerCase();
  const { pathname } = request.nextUrl;

  if (host === supportDomain && !pathname.startsWith("/support")) {
    const url = request.nextUrl.clone();
    url.pathname = `/support${pathname === "/" ? "" : pathname}`;
    return NextResponse.rewrite(url);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next|api|favicon.ico|robots.txt|sitemap.xml).*)"],
};
