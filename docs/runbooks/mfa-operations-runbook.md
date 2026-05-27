# MFA Operations Runbook

- Scope: TOTP-based multi-factor authentication on the admin dashboard
  (`services/dashboard-auth`) and the customer portal (`services/control-plane`).
- Audience: platform operators and tenant administrators.
- Related code: `libs/cyberarmor-core/cyberarmor_core/crypto/totp.py`,
  endpoints under `/me/totp/*` (admin) and `/customer/me/totp/*` (tenant),
  per-tenant flag at `TenantPortalConfig(section="mfa")`.

## Policy and defaults

1. MFA is **optional** at both portals.
1. Admin dashboard: per-user opt-in.
1. `ADMIN_DASHBOARD_MFA_REQUIRED=true` upgrades this to per-policy
   enforcement (set when ready to require MFA for all operators).
1. Customer portal: a tenant_admin first turns on the per-tenant flag,
   then each user in that tenant independently enrolls.
1. Login is challenged only when **both** layers are true for that user.
1. Cryptography.
1. TOTP secrets are encrypted at rest with Fernet.
1. The KEK is derived per-service via PBKDF2-HMAC-SHA256 (120k iterations)
   from the service's session secret (`ADMIN_DASHBOARD_SESSION_SECRET`
   for the admin dashboard, `CUSTOMER_PORTAL_SESSION_SECRET` —
   falling back to `CYBERARMOR_JWT_SECRET` — for the customer portal).
1. Admin and tenant secrets are not cross-decryptable. This is intentional.
1. Rate limiting.
1. 5 failed attempts per MFA ticket → ticket invalidated, user must restart
   sign-in. Tunable via `CUSTOMER_PORTAL_MFA_MAX_ATTEMPTS`.
1. With `REDIS_URL` set, the counter is shared across uvicorn workers.
   Without Redis, the counter is per-process — acceptable for single-worker
   dev, not for production fleets with multiple workers.

## Tunable environment variables

1. Admin dashboard (`services/dashboard-auth`).
1. `ADMIN_DASHBOARD_SESSION_SECRET` — used as the TOTP KEK seed and the
   session signer. Rotating this invalidates **all** enrolled admin secrets.
1. `ADMIN_DASHBOARD_MFA_REQUIRED` — `true` forces enrollment.
1. `ADMIN_DASHBOARD_MFA_ISSUER` — label shown in the authenticator app.
1. `ADMIN_DASHBOARD_MFA_TICKET_TTL_SECONDS` — default 300.
1. Customer portal (`services/control-plane`).
1. `CUSTOMER_PORTAL_SESSION_SECRET` — TOTP KEK seed for tenant users.
   Rotating this invalidates **all** enrolled tenant-user secrets across
   every tenant.
1. `CUSTOMER_PORTAL_MFA_TICKET_TTL_SECONDS` — default 300.
1. `CUSTOMER_PORTAL_MFA_ISSUER` — label shown in the authenticator app.
1. `CUSTOMER_PORTAL_MFA_MAX_ATTEMPTS` — default 5.
1. `REDIS_URL` — if set and reachable at startup, the rate-limit counter
   uses Redis (shared across workers). Otherwise an in-process dict is
   used. Mid-request Redis failures fail closed (return 429).

## Day-2 procedures

### Enroll an admin

1. Operator signs in to the admin dashboard.
1. Navigate to **Account Security** in the left nav.
1. Click **Set up authenticator app** and scan the QR code with Google
   Authenticator, Microsoft Authenticator, 1Password, or similar.
1. Enter the 6-digit code shown by the app and click **Confirm**.
1. Copy the 10 displayed backup codes to a password manager. They are
   shown once — they cannot be retrieved later.
1. Click **I've saved them — continue**.
1. On next sign-in, after the email code step, the dashboard will prompt
   for the authenticator code (or any backup code).

### Enable MFA for a customer tenant

1. A user with `tenant_admin` role signs in to the customer portal for
   that tenant.
1. Navigate to **Customer Settings**.
1. In the **Multi-factor authentication** card, check
   **Make MFA available to users in this tenant**.
1. Each user in that tenant now sees their own enrollment UI in the same
   Settings page and can opt in individually. Sign-in is only challenged
   for users who have actually enrolled — turning the flag on does not
   force anyone.

### Tenant-admin force-disable MFA for a user (lost authenticator + backup codes)

1. Tenant_admin signs in to the customer portal.
1. Navigate to **Users**.
1. Find the row for the affected user; if their MFA is on, a **Reset MFA**
   button is present at the right end of the row.
1. Click **Reset MFA** and confirm.
1. The endpoint `POST /customer/users/{user_id}/disable-mfa` is invoked.
   It clears the user's `totp_secret_enc`, `totp_pending_enc`,
   `totp_enabled`, and `backup_codes_hash` fields. The action is logged
   server-side as a `WARNING` with both the acting admin and the target
   user identified.
1. The user can now sign in with just their email code. They should
   re-enroll from their own Settings page immediately afterward.
1. Tenant admins cannot use this endpoint on themselves. To disable their
   own MFA they must go through Account Security in Settings, which
   requires a current 6-digit code or backup code.

### Tenant-admin disables the per-tenant MFA flag

1. Tenant_admin un-checks **Make MFA available to users in this tenant**.
1. Effect: no user in this tenant is challenged at sign-in, even those
   who had previously enrolled.
1. Existing enrolled secrets are **preserved** (not wiped). Re-enabling
   the flag restores the challenge for those users without re-enrollment.
1. This is a recoverable break-glass — it does not constitute "disable
   MFA for a user." Use the per-user **Reset MFA** flow above for that.

## Incident playbooks

### A user lost their authenticator app and their backup codes

1. Verify the requesting user's identity through an out-of-band channel
   (existing helpdesk procedure, IT-issued device, manager attestation —
   whatever your organization already uses for password reset).
1. As tenant_admin (customer portal) or platform operator (admin dashboard),
   force-disable MFA for the user.
1. Customer portal: use the **Reset MFA** button in **Users**.
1. Admin dashboard: there is no equivalent self-service UI today.
   Operators must clear the four TOTP columns on the affected
   `admin_users` row directly via a DB session (`psql` or the
   equivalent). Document the action in your incident system.
1. Instruct the user to re-enroll at next sign-in.

### Suspected secret rotation needed for compromised KEK material

1. Decide whether the compromise affects the admin dashboard secret,
   the customer portal secret, or both.
1. Communicate the planned downtime / re-enrollment ask to affected users.
1. Rotate the relevant session secret in your secrets store.
1. `ADMIN_DASHBOARD_SESSION_SECRET` for admins.
1. `CUSTOMER_PORTAL_SESSION_SECRET` for tenant users (falls back to
   `CYBERARMOR_JWT_SECRET` if unset — set it explicitly before rotation
   so the rotation is scoped).
1. Roll the deployment.
1. Effect: all previously enrolled TOTP secrets become undecryptable.
   The first login attempt by any enrolled user will produce a
   `cryptography.fernet.InvalidToken` error in the logs and a generic
   401 to the user.
1. Recovery options.
1. **Bulk reset (recommended)**: run a one-off DB script that clears
   `totp_secret_enc`, `totp_pending_enc`, `totp_enabled`, and
   `backup_codes_hash` on every affected row. Users re-enroll on next
   sign-in (and, in tenants with the per-tenant flag still on, will
   be prompted to do so right after the email-code step succeeds).
1. **Per-user reset**: surface the issue to support and clear on
   request via the force-disable UI / direct SQL.
1. Verify by signing in as a test user and confirming the enrollment
   flow appears as expected.

### Rate limit appears stuck (legitimate user reporting "MFA service temporarily unavailable")

1. Check control-plane logs for `mfa_rate_limit redis_error_on_*` lines.
1. If Redis is unreachable, the rate-limit code path fails closed and
   returns 429. This is intentional: it prevents an attacker from
   disabling the limit by tickling Redis.
1. Restore Redis connectivity (or temporarily clear `REDIS_URL` and
   roll the service, which falls back to the in-process counter — only
   acceptable for short-term recovery on a single-worker deployment).
1. Confirm by inspecting the next request's response status returns to
   200/401 (not 429) for valid/invalid codes respectively.

## Verification checklist

1. Both services start successfully.
1. Admin dashboard exposes `/me/totp/status` and returns
   `{"totp_enabled": false, "mfa_required": <env value>}` for a signed-in
   admin.
1. Control plane exposes `/customer/me/totp/status` and returns
   `{"totp_enabled": false, "mfa_available_for_tenant": false}` for a
   signed-in tenant user in a tenant where the flag is off.
1. Tenant-admin can flip `/customer/config/mfa` and the per-user status
   endpoint reflects the change.
1. Enrolling a test user produces a valid QR code (the `qr_svg` field
   begins with `<svg`).
1. After enrollment, signing out and signing back in returns
   `{"mfa_required": true}` and sets the `ca_customer_mfa` /
   `ca_dashboard_mfa` cookie.
1. `/verify-totp` accepts a TOTP code and issues the real session cookie.
1. Same endpoint also accepts a backup code (and decrements
   `backup_codes_remaining`).
1. 5 consecutive bad submissions to `/verify-totp` produce a 429.
1. With `REDIS_URL` set, the counter is visible in Redis under
   `mfa:fails:<sha256>` keys with a TTL ≤ the ticket TTL.

## Out of scope (today)

1. WebAuthn / passkeys / hardware keys.
1. SMS or email-as-second-factor.
1. Forcing MFA tenant-wide (the per-tenant flag controls *availability*,
   not *requirement* — users still opt in individually).
1. Admin-dashboard equivalent of the customer-portal force-disable UI.
