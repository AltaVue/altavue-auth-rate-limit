# @comet/auth-rate-limit

Shared internal rate limiter for the AltaVue platform's **unauthenticated
auth-email endpoints**. One implementation, consumed by both the Launcher and
the Customer Portal, so the two can never drift apart.

Origin: AO-50 (Platform-Wide Rate Limiting). Implements the fix for SEC-008 /
AO-271. Previously this exact logic lived as two hand-copied files
(`comet-launcher/lib/email/authEmailRateLimit.ts` and
`comet-customer-portal/src/lib/authEmailRateLimit.ts`); this package is now the
single source of truth.

## What it protects

Three public endpoints send real email through Resend with no account required:

| Route tag                  | Endpoint                                |
| -------------------------- | --------------------------------------- |
| `launcher-magic-link`      | Launcher `POST /api/auth/magic-link`    |
| `launcher-reset-password`  | Launcher `POST /api/auth/reset-password`|
| `portal-magic-link`        | Portal `POST /api/auth/magic-link`      |

## Caps

- **Per email:** 3 sends / 15 minutes — across **all** routes combined.
- **Per IP:** 10 requests / hour — IP stored only as an HMAC-SHA256 keyed by
  the server-only `RATE_LIMIT_IP_KEY` secret (AO-2085). Every app that imports
  this package must set that secret, with a different value per environment.
  Without it the package refuses to rate-limit by IP at all (the per-email
  cap still applies) rather than fall back to an unkeyed hash.

All three routes count against **one shared table**
(`public.auth_email_request_log`, created by migration `0209` in
`comet-launcher/supabase/migrations`) on the shared Supabase project both apps
point at. Over a cap, the route returns its normal generic response and skips
the send — the caller cannot tell it was throttled. On a DB error the check
**fails open** (allows the send): this guards cost and abuse, not
authentication, so a database hiccup must never lock a real user out.

## Usage

```ts
import { checkAuthEmailRateLimit } from '@comet/auth-rate-limit'

const allowed = await checkAuthEmailRateLimit(
  serviceClient,          // service-role Supabase client
  'launcher-magic-link',  // the calling route's tag
  email,                  // trimmed + lowercased
  req                     // the incoming NextRequest (IP headers only)
)
if (!allowed) return genericResponse() // over a cap → respond, do not send
```

## Consuming it

Add as a pinned git dependency (same mechanism as `@comet/ui`):

```json
"@comet/auth-rate-limit": "git+https://github.com/mmcdaniel-saber/comet-auth-rate-limit.git#v0.2.0"
```

`next` and `@supabase/supabase-js` are **peer dependencies** and are used only
for types — the consuming app already provides both. The package ships raw
TypeScript from `src/` with no build step.

## Tests

Behavioural coverage lives in `comet-tests`
(`tests/unit/auth-email-rate-limit.spec.ts`), which imports this package's
source directly, plus an opt-in HTTP side-channel test
(`tests/integration/auth-email-rate-limit-endpoint.spec.ts`).

## Releasing

Bump `version`, commit, tag `vX.Y.Z`, push the tag, then bump the `#vX.Y.Z`
ref in each consuming app's `package.json` and reinstall.
