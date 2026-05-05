import type { NextConfig } from "next";

const ContentSecurityPolicy = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://us.i.posthog.com https://app.posthog.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  "img-src 'self' data: blob: https:",
  "connect-src 'self' https://us.i.posthog.com https://app.posthog.com",
  "worker-src blob:",
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "upgrade-insecure-requests",
].join("; ");

const securityHeaders = [
  // Prevent MIME-type sniffing
  { key: "X-Content-Type-Options", value: "nosniff" },
  // Block clickjacking
  { key: "X-Frame-Options", value: "DENY" },
  // Control referrer information
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  // Disable unnecessary browser features
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), browsing-topics=(), interest-cohort=()",
  },
  // Content Security Policy
  { key: "Content-Security-Policy", value: ContentSecurityPolicy },
  // HSTS — enforced once on HTTPS (nginx will also set this; belt-and-suspenders)
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
  // Prevent XSS attacks in older browsers
  { key: "X-XSS-Protection", value: "1; mode=block" },
  // DNS prefetch control
  { key: "X-DNS-Prefetch-Control", value: "on" },
];

const nextConfig: NextConfig = {
  // Emit a standalone build that bundles only the runtime files needed
  // to serve the app. Lets the Docker image stay small.
  output: "standalone",

  // Remove the X-Powered-By: Next.js header to avoid fingerprinting
  poweredByHeader: false,

  // Apply security headers to all routes
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: securityHeaders,
      },
    ];
  },

  // Compress responses
  compress: true,

  // Strict mode for React
  reactStrictMode: true,
};

export default nextConfig;
