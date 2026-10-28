// @comet/auth-rate-limit
//
// Rate limiting for the unauthenticated auth-email endpoints across the
// AltaVue platform:
//
//   • Launcher  POST /api/auth/magic-link      (route tag 'launcher-magic-link')
//   • Launcher  POST /api/auth/reset-password  (route tag 'launcher-reset-password')
//   • Portal    POST /api/auth/magic-link      (route tag 'portal-magic-link')
//
// Why this exists: every one of these endpoints is reachable without an
// account and each sends a real email through Resend. Unlimited, they let
// anyone bomb a customer's inbox, burn the Resend quota, or damage the sender
// reputation. Found by the 2026-07-27 platform-wide rate limiting scan
// (SEC-008 / AO-271); consolidated into this shared package under AO-50 so the
// Launcher and Portal can never drift apart again.
//
// How it works: before sending, the route calls checkAuthEmailRateLimit(). The
// helper counts recent rows in public.auth_email_request_log (migration 0209 in
// comet-launcher, on the SHARED Supabase project both apps point at):
//
//   • per-email : max 3 sends in 15 minutes, across ALL auth-email routes
//                 (Launcher magic-link + reset-password + Portal magic-link
//                 share the table, so alternating endpoints doesn't help an
//                 attacker).
//   • per-IP    : max 10 requests per hour. The IP is never stored in a form
//                 that can be turned back into an address — see below.
//
// Under both caps → the request is recorded and allowed. Over either → the
// route returns its usual generic "if an account exists..." message and
// silently skips the send, so callers can't tell they were throttled and
// learn nothing about which accounts exist.
//
// FAIL-OPEN by design: if the check itself errors (table not migrated yet on
// an env, transient DB error) we log loudly and allow the send. This limiter
// guards cost and abuse, not authentication — a database hiccup must never
// lock users out of signing in.
//
// AO-2085 (28 Oct 2026): the IP used to be stored as a plain SHA-256 hash,
// which is reversible in minutes — SHA-256 has no secret, so anyone with a
// copy of the table can hash every possible IPv4 address and match it back.
// It is now an HMAC-SHA256 keyed by a server-only secret, RATE_LIMIT_IP_KEY,
// set as an environment variable on every app that imports this package.
// Without that secret the stored values cannot be reversed; rotating it only
// resets everyone's rate-limit window. If the secret is missing, this package
// refuses to rate-limit by IP at all (the per-email cap still applies) and
// logs a loud error — it never falls back to the old unkeyed hash.
//
// This package ships raw TypeScript (no build step) and is consumed as a
// pinned git dependency, exactly like @comet/ui. `next` and
// @supabase/supabase-js are peer dependencies and are only used for types.

import { createHmac } from 'crypto'
import type { NextRequest } from 'next/server'
import type { SupabaseClient } from '@supabase/supabase-js'

const RATE_LIMIT_IP_KEY_ENV = 'RATE_LIMIT_IP_KEY'

export const AUTH_EMAIL_LIMIT = 3 // sends per email
export const AUTH_EMAIL_WINDOW_MS = 15 * 60 * 1000 // 15 minutes
export const AUTH_IP_LIMIT = 10 // requests per IP
export const AUTH_IP_WINDOW_MS = 60 * 60 * 1000 // 1 hour

const PURGE_AFTER_MS = 2 * 24 * 60 * 60 * 1000 // keep rows ~2 days
const PURGE_PROBABILITY = 0.05 // ~1 in 20 allowed calls also sweeps old rows

export type AuthEmailRoute =
  | 'launcher-magic-link'
  | 'launcher-reset-password'
  | 'portal-magic-link'

/**
 * Extract the caller's IP from the proxy headers Vercel sets and return a
 * keyed HMAC-SHA256 of it, using the server-only RATE_LIMIT_IP_KEY secret.
 * Returns null when no IP header is present, OR when the secret is not
 * configured — in both cases the per-IP cap is skipped for this request and
 * only the per-email cap applies. Raw IPs are never stored or logged, and a
 * missing secret never falls back to an unkeyed hash.
 */
export function hashClientIp(req: NextRequest): string | null {
  const forwarded = req.headers.get('x-forwarded-for')
  const ip = forwarded?.split(',')[0]?.trim() || req.headers.get('x-real-ip')?.trim() || ''
  if (!ip) return null

  const key = process.env[RATE_LIMIT_IP_KEY_ENV]
  if (!key) {
    console.error(
      `[auth-email-rate-limit] ${RATE_LIMIT_IP_KEY_ENV} is not set — refusing to rate-limit ` +
        'by IP for this request (the per-email cap still applies). Set this secret in every ' +
        'environment before relying on the per-IP cap.'
    )
    return null
  }

  return createHmac('sha256', key).update(ip).digest('hex')
}

/**
 * Returns true when this request may proceed to send an email, false when it
 * is over a cap and the route should return its generic response WITHOUT
 * sending. Never throws; errors fail open (allowed) with a loud log line.
 *
 * @param serviceClient  Service-role Supabase client (the table is RLS-locked
 *                       to the server; anon/authenticated roles cannot touch it).
 * @param route          Which endpoint is asking (diagnostic only).
 * @param email          The requested email, already trimmed + lowercased.
 * @param req            The incoming request (used only for the IP headers).
 */
export async function checkAuthEmailRateLimit(
  serviceClient: SupabaseClient,
  route: AuthEmailRoute,
  email: string,
  req: NextRequest
): Promise<boolean> {
  try {
    const now = Date.now()
    const emailWindowStart = new Date(now - AUTH_EMAIL_WINDOW_MS).toISOString()
    const ipWindowStart = new Date(now - AUTH_IP_WINDOW_MS).toISOString()
    const ipHash = hashClientIp(req)

    const [emailRes, ipRes] = await Promise.all([
      serviceClient
        .from('auth_email_request_log')
        .select('id', { count: 'exact', head: true })
        .eq('email', email)
        .gte('created_at', emailWindowStart),
      ipHash
        ? serviceClient
            .from('auth_email_request_log')
            .select('id', { count: 'exact', head: true })
            .eq('ip_hash', ipHash)
            .gte('created_at', ipWindowStart)
        : Promise.resolve({ count: 0, error: null }),
    ])

    if (emailRes.error || ipRes.error) {
      console.error(
        `[auth-email-rate-limit] count failed for ${route} (failing open):`,
        emailRes.error ?? ipRes.error
      )
      return true
    }

    if ((emailRes.count ?? 0) >= AUTH_EMAIL_LIMIT || (ipRes.count ?? 0) >= AUTH_IP_LIMIT) {
      // Deliberately quiet toward the caller; loud in our own logs.
      console.warn(
        `[auth-email-rate-limit] throttled ${route} (email window: ${emailRes.count ?? 0}/${AUTH_EMAIL_LIMIT}, ip window: ${ipRes.count ?? 0}/${AUTH_IP_LIMIT})`
      )
      return false
    }

    // Under both caps: record this allowed request. Refused attempts are NOT
    // recorded, so an attacker can't keep a victim's window pinned forever —
    // it always clears 15 minutes after the last real send.
    const { error: insErr } = await serviceClient
      .from('auth_email_request_log')
      .insert({ route, email, ip_hash: ipHash })
    if (insErr) {
      console.error(`[auth-email-rate-limit] insert failed for ${route} (non-fatal):`, insErr)
    }

    // Opportunistic purge so the table never needs a cron job.
    if (Math.random() < PURGE_PROBABILITY) {
      const cutoff = new Date(now - PURGE_AFTER_MS).toISOString()
      const { error: purgeErr } = await serviceClient
        .from('auth_email_request_log')
        .delete()
        .lt('created_at', cutoff)
      if (purgeErr) console.error('[auth-email-rate-limit] purge failed (non-fatal):', purgeErr)
    }

    return true
  } catch (err) {
    console.error(`[auth-email-rate-limit] check crashed for ${route} (failing open):`, err)
    return true
  }
}
