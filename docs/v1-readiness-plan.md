# CyberArmor V1 Readiness Plan

This document separates three things:

- what the repo can do today
- what we should finish now to deploy a useful internal test environment
- what still needs to change before `v1` is ready for first customers

## 1. Bottom Line

Deploying the current stack to a Hetzner Ubuntu VM is a good next step if the goal is to:

- validate real deployment behavior
- test the dashboard and service interactions outside local Docker Desktop
- exercise detection, policy, runtime, and Ollama-backed flows
- start collecting the operational gaps we need to close

If the goal is "launch to first paying customers," deployment alone is not enough. The biggest gap is not core detection logic. It is customer-facing identity, onboarding, tenant administration, and separation between customer and operator surfaces.

## 2. What We Have Today

The current repo already gives us:

- a Docker Compose deployment path
- core services for control plane, policy, detection, response, compliance, proxy, and identity enrichment
- a tenant model in the control plane
- tenant-aware policy endpoints
- an admin-style dashboard SPA
- support for identity provider enrichment integrations
- local ML detection using Hugging Face models
- optional Ollama second-pass judgement

The current repo does not yet appear to provide a full customer authentication product:

- no dedicated tenant login application for `app.cyberarmor.ai`
- no self-service tenant signup flow
- no UI-driven tenant onboarding wizard
- no complete email/password account system with MFA
- no per-tenant SSO configuration workflow in the app
- no strong separation between global CyberArmor operator administration and tenant administration

## 3. What We Should Finish Today

If the goal is to deploy what we have and start testing, these are the highest-value tasks to finish today:

### 3.1 Deployment and Ops

- deploy the stack to the Hetzner VM
- replace all insecure default secrets
- front the dashboard with HTTPS
- lock down host firewall rules
- ensure Docker services restart on reboot
- confirm Postgres data persists across restarts
- pre-download Ollama and Hugging Face models
- run `scripts/smoke-test.sh` successfully on the server

### 3.2 Environment Boundaries

- reserve `cyberarmor.ai` for operator/global admin use
- reserve `app.cyberarmor.ai` for the future tenant-facing app
- document that both may currently point to the same stack for testing, but are not logically equivalent long-term

### 3.3 Tenant Testing Workflow

- create at least one test tenant through the control-plane API
- generate tenant-scoped API keys
- verify tenant-scoped policy evaluation
- verify tenant-specific dashboard data access assumptions

### 3.4 Product Truthfulness

- document clearly that customer onboarding is still manual
- document clearly that tenant auth is not yet self-service
- avoid presenting the current dashboard as a completed customer portal

## 4. What Must Change Before V1 for First Customers

The work below is the real v1 boundary.

## 5. Split the Product Into Two Web Surfaces

You asked specifically to separate tenant environments from the global admin dashboard. I think that is the right direction.

Target split:

- `cyberarmor.ai`: CyberArmor internal/global admin console
- `app.cyberarmor.ai`: customer tenant application

### Global admin should handle

- overall platform operations
- tenant provisioning and lifecycle state
- support access
- deployment health
- billing hooks later
- global security analytics across tenants if contractually allowed

### Tenant app should handle

- tenant login
- tenant admins and users
- tenant-specific policy views
- SSO configuration
- local user and MFA management
- API key generation for that tenant
- onboarding workflows and agent enrollment

This should be enforced both in UX and in backend authorization.

## 6. Automate Tenant Setup at `app.cyberarmor.ai`

For v1, tenant creation should be a workflow, not an API-only operator task.

Recommended onboarding flow:

1. Tenant admin starts setup at `app.cyberarmor.ai/signup` or receives an invited activation link.
2. System creates a tenant record and default configuration.
3. System creates a tenant admin account or starts SSO setup.
4. System provisions tenant defaults:
   - baseline policies
   - default roles
   - default API keys or guided credential creation
   - default retention and notification settings
5. Tenant admin lands in a guided onboarding checklist.

Minimum automation needed:

- create tenant record
- create tenant admin role bindings
- create default policy pack
- create default dashboard configuration
- create audit trail entries for provisioning
- create or configure auth mode for that tenant

## 7. Authentication Modes for V1

You asked for both SSO and individual email-based accounts with MFA. V1 should support both.

### Option A: Tenant SSO

Recommended for business customers.

Tenant admin flow:

1. Log into the tenant app with an initial bootstrap account or invitation.
2. Choose identity provider:
   - Microsoft Entra ID
   - Okta
   - Ping
   - other later
3. Enter issuer/client details or upload metadata.
4. Verify domain ownership or callback URL setup.
5. Test sign-in with a sample user.
6. Enforce SSO for the tenant.

What needs to exist in the product:

- tenant-scoped SSO configuration model
- secure secret storage for IdP client secrets
- redirect/callback handlers
- role mapping from IdP groups/claims to CyberArmor roles
- tenant-scoped session and logout handling
- recovery path for tenant admins

### Option B: Individual Email Accounts with MFA

Recommended as fallback and for smaller teams.

User flow:

1. User is invited by tenant admin or self-registers if allowed.
2. User verifies email.
3. User sets password.
4. User enrolls MFA before full access is granted.
5. User signs in to the tenant app.

What needs to exist in the product:

- user table and credential lifecycle
- password hashing and reset flow
- email verification flow
- TOTP or WebAuthn MFA
- backup codes
- session management
- role-based access control
- account lockout and audit logging

Recommendation:

- V1 should require MFA for all tenant admins.
- TOTP is the fastest first MFA option.
- WebAuthn can come after v1 if needed.

## 8. Suggested Tenant Roles for V1

- `tenant_owner`
- `tenant_admin`
- `security_analyst`
- `readonly_auditor`
- `integration_admin`

Global roles should be separate:

- `platform_super_admin`
- `platform_ops`
- `support_engineer`

Do not reuse the same UI and permissions model for both surfaces.

## 9. How Adding a New Tenant Should Work in V1

Here is the user-friendly target flow.

### Path 1: SSO tenant

1. CyberArmor operator creates a tenant invitation or the customer starts from a sign-up page.
2. Tenant is provisioned with a temporary bootstrap admin.
3. Tenant admin signs into `app.cyberarmor.ai`.
4. Tenant admin chooses `Set up SSO`.
5. Tenant admin selects provider and enters metadata.
6. System validates redirect URI and performs a test login.
7. Tenant admin maps groups to CyberArmor roles.
8. Tenant admin turns on `Require SSO`.
9. System keeps one emergency break-glass local admin under strict controls.

### Path 2: Email + MFA tenant

1. Tenant is created.
2. Tenant admin receives invitation email.
3. Tenant admin verifies email and creates password.
4. Tenant admin is forced to enroll MFA.
5. Tenant admin invites additional users by email.
6. Invited users verify email, create password, and enroll MFA.
7. Tenant admin assigns roles in the tenant portal.

## 10. What We Need to Build or Change

The repo likely needs the following additions for v1.

### Backend

- tenant-scoped user/account service
- invitation service
- MFA enrollment and verification endpoints
- session/token service for customer login
- tenant-scoped SSO config storage
- tenant role mapping and RBAC enforcement
- stronger tenant scoping in every service boundary
- secret storage strategy for IdP credentials

### Frontend

- a separate tenant-facing app for `app.cyberarmor.ai`
- login, signup, invite acceptance, password reset, MFA screens
- onboarding checklist UI
- SSO setup wizard
- tenant settings and user management views
- tenant-specific policy and integration pages without global admin controls

### Infrastructure

- separate frontend deployment targets for global admin and tenant app
- separate auth/session configuration
- email delivery provider for invites and resets
- TLS everywhere
- backup and disaster recovery
- monitoring and alerting

## 11. Recommended Delivery Sequence

If we want momentum without overbuilding, I’d sequence it like this:

1. Deploy the current stack to Hetzner and validate end-to-end testing.
2. Lock the product boundary:
   - global admin at `cyberarmor.ai`
   - tenant app at `app.cyberarmor.ai`
3. Build tenant auth foundation:
   - local accounts
   - MFA
   - tenant RBAC
4. Build tenant provisioning automation.
5. Build tenant SSO setup wizard.
6. Move customer-facing workflows out of the current global admin SPA.
7. Run a controlled pilot with a small number of tenants.

## 12. My Recommendation

Yes, deploying to a Hetzner Ubuntu VM for testing is a good next step.

But I would not make it the only next step.

The best paired plan is:

- deploy now so we can test the stack in a realistic environment
- immediately follow that with product work to create the tenant-facing auth and onboarding surface

If we skip the deployment, we stay too theoretical.
If we only deploy and do not tackle tenant onboarding/auth, we risk polishing the wrong layer.

So the next move I’d recommend is:

1. deploy the current stack for internal testing
2. treat `app.cyberarmor.ai` tenant onboarding/auth separation as the next highest-priority v1 feature

That combination gives us both operational truth and product truth.
