# Security Review (2026-03)

This document captures a targeted security review of the repository, with concrete risks and recommended mitigations.

## Key risks

1. **Workspace isolation gaps in several endpoints**
   - `GET /api/gateways` and related gateway mutations operate on a `gateways` table without `workspace_id` scoping.
   - `GET /api/tokens` loads token usage rows without filtering by caller workspace.
   - `GET /api/export` scopes `tasks` and `activities`, but not `audit` and `pipelines` exports.

   **Impact:** data leakage across tenants/workspaces, and potential cross-workspace configuration tampering.

2. **Sensitive secret storage in plaintext**
   - Webhook secrets are persisted as plaintext (`webhooks.secret`).
   - Integration credentials are written directly to an OpenClaw `.env` file.
   - Gateway tokens are persisted in DB without encryption.

   **Impact:** any DB or filesystem compromise yields reusable credentials/tokens immediately.

3. **Global API key maps directly to synthetic admin user**
   - `x-api-key` authentication grants a synthetic `admin` principal for all API routes that rely on `requireRole`.

   **Impact:** single static secret becomes a universal admin credential, with no per-user attribution/scoping and higher blast radius.

4. **Trust boundary inconsistency for client IP handling**
   - Some routes read `x-forwarded-for` directly for audit/session metadata.
   - There is safer proxy-aware logic (`extractClientIp`) but it is not consistently used in these routes.

   **Impact:** spoofable IP entries in audit trails and noisy/incorrect incident forensics.

5. **Webhook delivery can be used as SSRF primitive**
   - Webhook targets are admin-configurable URLs and are fetched server-side without explicit private-address or allowlist controls.

   **Impact:** attackers with admin/session compromise could probe internal network services and cloud metadata endpoints.

## Recommended improvements (priority order)

## P0 (high)

- Enforce workspace scoping everywhere:
  - Add `workspace_id` to `gateways` table and scope all gateway queries/mutations by caller workspace.
  - Filter `token_usage` reads/writes by workspace in `/api/tokens`.
  - Scope `audit` and `pipelines` exports by workspace (or explicitly gate those types to super-admin only).

- Replace single global API key model:
  - Move to per-user/per-service API tokens with hashed-at-rest storage, scope (read/write/admin), expirations, and revocation.
  - Add audit attribution for token identity, not just synthetic `api` user.

## P1 (medium)

- Harden secrets at rest:
  - Encrypt webhook secrets and gateway tokens using a server-side encryption key (`MC_ENCRYPTION_KEY`) with key rotation support.
  - Prefer secret manager/Vault over plaintext `.env` writes where possible; if `.env` must remain, enforce restrictive file permissions and avoid logging secret values.

- Normalize IP extraction:
  - Introduce a shared helper that all routes use for audit/session IP capture (reuse `extractClientIp`).
  - Define and document trusted proxy chain configuration (`MC_TRUSTED_PROXIES`) for production.

## P2 (defense-in-depth)

- Add outbound webhook egress controls:
  - Block link-local, loopback, RFC1918, and cloud metadata ranges by default.
  - Add explicit outbound allowlist option for webhook destinations.

- Add security regression tests:
  - Multi-workspace tests proving non-admin users cannot read another workspace’s gateway/token/export data.
  - Unit tests for IP extraction consistency.
  - SSRF safety tests for webhook URL validation/egress policy.

## Implemented hardening updates (this repo revision)

- Added workspace scoping for `/api/gateways` CRUD and default seeding behavior by persisting `workspace_id` and filtering all reads/writes by the caller workspace.
- Updated `/api/tokens` to scope database/file-backed usage records by workspace and avoid non-scoped in-memory fallback outside the default workspace.
- Scoped `/api/export` for `pipelines` by `workspace_id`, and tightened `audit` exports to workspace-bound records (using `workspace_id` when available, with actor-based fallback for legacy rows).
- Added migration `024_audit_log_workspace_scope` to add/index `audit_log.workspace_id` and backfill from `users.workspace_id` when `actor_id` is present.
- Updated `logAuditEvent` to persist `workspace_id` for new audit records (explicit or derived from actor).
