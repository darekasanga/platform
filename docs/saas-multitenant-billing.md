# SaaS multi-tenant domain & billing design

This document outlines how to add multi-tenant domain routing, billing, and admin usage visibility for the platform running on Vercel with a Next.js App Router stack.

## Goals

- Allow orgs to provision tenants on `emperor.gallery` with wildcard subdomains (e.g., `team-a.emperor.gallery`) without DNS changes.
- Prepare for custom domains per tenant via Vercel for Platforms domain management.
- Implement subscription billing with Stripe (checkout, customer portal, webhook sync) and usage tracking to support usage-based pricing.
- Provide an admin dashboard for owners/admins showing usage, run quality, and billing posture.

## Domain and tenancy strategy

- **Vercel setup**: Add apex `emperor.gallery` and wildcard `*.emperor.gallery` to the Vercel project (requires Vercel name servers). Vercel forwards the original `Host` header, which is relied upon for tenant resolution.
- **Host parsing**: Extract the subdomain in middleware for every request and resolve the tenant. Reject unknown/invalid hosts with `404`.
- **Reserved/invalid slugs**: `www`, `admin`, `api`, `app`, `static`, `assets`, `vercel`, and any slug containing characters outside `[a-z0-9-]` or repeated/leading/trailing hyphens are rejected.
- **Tenant creation**: Creating a tenant only inserts a `Tenant.slug`; no DNS work is required because of the wildcard domain.
- **Custom domains** (future): `DomainMapping` records track ownership and link to Vercel domain management APIs for verification/aliasing.

### Next.js middleware (conceptual)

```ts
// middleware.ts
import { NextResponse } from 'next/server'
import { getTenantBySlug, getDomainMapping } from './lib/tenancy'

const RESERVED = new Set(['www', 'admin', 'api', 'app', 'static', 'assets', 'vercel'])

export async function middleware(req: NextRequest) {
  const host = req.headers.get('host') ?? ''
  const [subdomain] = host.split(':')[0].split('.')

  if (!subdomain || RESERVED.has(subdomain) || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(subdomain)) {
    return NextResponse.rewrite(new URL('/404', req.url))
  }

  const tenant = await getTenantBySlug(subdomain)
  const mappedDomain = await getDomainMapping(host)

  if (!tenant && !mappedDomain) {
    return NextResponse.rewrite(new URL('/404', req.url))
  }

  req.nextUrl.searchParams.set('tenantId', mappedDomain?.tenantId ?? tenant!.id)
  return NextResponse.next({ request: { headers: req.headers } })
}
```

`getDomainMapping` should look up both `type=subdomain` (for `*.emperor.gallery`) and `type=custom` domains to support future custom hostnames.

## Data model

Prisma-style schema (adapt for your ORM):

```prisma
model Tenant {
  id        String   @id @default(cuid())
  orgId     String   @unique
  slug      String   @unique
  createdAt DateTime @default(now())
  domainMappings DomainMapping[]
}

model DomainMapping {
  id        String   @id @default(cuid())
  tenantId  String
  domain    String   @unique
  type      DomainType // enum: SUBDOMAIN | CUSTOM
  status    DomainStatus // enum: PENDING | VERIFIED | ACTIVE | ERROR
  createdAt DateTime @default(now())
  tenant    Tenant   @relation(fields: [tenantId], references: [id])
}

model Subscription {
  id                  String   @id @default(cuid())
  orgId               String   @unique
  stripeCustomerId    String   @unique
  stripeSubscriptionId String  @unique
  plan                Plan     // enum: FREE | PRO | TEAM
  status              SubscriptionStatus // ACTIVE | PAST_DUE | CANCELED | INCOMPLETE
  currentPeriodEnd    DateTime
  createdAt           DateTime @default(now())
  billingAdminUserId  String?
}

model UsageLedger {
  id               String   @id @default(cuid())
  orgId            String
  periodStart      DateTime
  periodEnd        DateTime
  runs             Int
  promptTokens     Int
  completionTokens Int
  estimatedCost    Decimal @db.Decimal(10, 4)
  createdAt        DateTime @default(now())
}

model UsageEvent {
  id               String   @id @default(cuid())
  orgId            String
  runId            String
  stepId           String?
  provider         String
  model            String
  promptTokens     Int
  completionTokens Int
  durationMs       Int
  resultSize       Int // diff/pr body lines
  createdAt        DateTime @default(now())
}
```

Indexes to add:

- `Tenant.slug`, `DomainMapping.domain` for fast host resolution.
- `UsageEvent.orgId`, `UsageEvent.createdAt` for aggregation windows (7/30/90d).
- `UsageLedger.orgId+periodStart` for billing reconciliation.

## Billing flows (Stripe Billing)

- **Plans**: Free (e.g., 20 runs/month), Pro (e.g., 200 runs/month), Team (monthly base + seats + run cap). Plans map to Stripe Price IDs.
- **Checkout**: Route `/api/billing/checkout` creates a Stripe Checkout Session with the org’s `stripeCustomerId` and selected price IDs. Return the URL to the client.
- **Customer Portal**: `/api/billing/portal` creates a Stripe Billing Portal session for the org’s customer.
- **Webhook**: `/api/stripe/webhook` verifies the Stripe signature and updates `Subscription.status`, `currentPeriodEnd`, and `plan` on `invoice.payment_succeeded`, `customer.subscription.updated`, and `customer.subscription.deleted` events.
- **Billing admin**: Each org has a `billingAdminUserId` to gate access to billing actions and receive approaching-limit alerts.
- **Usage-based readiness**: `UsageEvent` rows are persisted per run/step; nightly jobs aggregate into `UsageLedger`. Stripe metered billing can later read from `UsageLedger` to report usage via the Usage Records API.

## Usage capture

- Capture per-run and per-step metrics:
  - `provider`, `model`
  - `promptTokens`, `completionTokens` (if provided by the LLM API)
  - `durationMs`
  - `resultSize` (e.g., diff/pr_body line count)
- Persist immediately in `UsageEvent`; roll up per org into `UsageLedger` for billing periods and dashboards.
- Derive cost estimates from provider/model rate cards stored in config.

## Admin dashboard (owner/admin only)

- **Usage & performance**: Runs by user, success rate, average duration; workflow-level execution counts and artifact generation rate; selectable windows (7/30/90 days).
- **Billing**: Current plan, next invoice date, Stripe status, consumption vs plan caps, and warnings at 80% of run/token limits.
- **Costs (estimated)**: Show per-provider/token usage with estimated spend; link out to Stripe customer portal.
- **Auditability**: Link dashboard aggregates back to underlying `UsageEvent` rows for inspection.

## Tenant settings

- Manage `Tenant.slug` (with collision checks and reserved-word enforcement).
- Show current subdomain URL and any custom domains (from `DomainMapping`).
- Expose an action to add a custom domain (future) that triggers Vercel domain creation/verification.

## Security and edge cases

- Validate the `Host` header against `DomainMapping` and reserved slugs; unknown hosts serve 404.
- Enforce Stripe webhook signature verification and idempotent updates to subscription state.
- Scope all usage writes by `tenantId`/`orgId` derived from middleware resolution to avoid cross-tenant leakage.
