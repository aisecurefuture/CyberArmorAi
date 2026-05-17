# syntax=docker/dockerfile:1.7
# Multi-stage build for the cyberarmor.ai marketing site (Next.js 16, standalone output).

FROM node:20-alpine AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:20-alpine AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1

# NEXT_PUBLIC_* vars must be present at build time — Next.js inlines them into
# the client bundle. Runtime env (env_file in compose) is too late for these.
ARG NEXT_PUBLIC_POSTHOG_KEY=phc_qjQVKKrn7YKbD7HFtdSXHqzt6NqypYqtw4ipzpw3x6MK
ARG NEXT_PUBLIC_POSTHOG_HOST=https://us.i.posthog.com
ARG NEXT_PUBLIC_GA_ID=G-NSZDCLCJ8P
ARG NEXT_PUBLIC_LINKEDIN_PARTNER_ID
ENV NEXT_PUBLIC_POSTHOG_KEY=$NEXT_PUBLIC_POSTHOG_KEY
ENV NEXT_PUBLIC_POSTHOG_HOST=$NEXT_PUBLIC_POSTHOG_HOST
ENV NEXT_PUBLIC_GA_ID=$NEXT_PUBLIC_GA_ID
ENV NEXT_PUBLIC_LINKEDIN_PARTNER_ID=$NEXT_PUBLIC_LINKEDIN_PARTNER_ID

COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3003
ENV HOSTNAME=0.0.0.0

RUN addgroup --system --gid 1001 nodejs \
 && adduser  --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3003
CMD ["node", "server.js"]
