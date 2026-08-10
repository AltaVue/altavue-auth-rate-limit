// @comet/auth-rate-limit — shared auth-email rate limiter for the AltaVue platform.
//
// The database-backed cap that protects the three unauthenticated endpoints
// that send real Resend email (Launcher magic-link + reset-password, Portal
// magic-link). Consolidated from two hand-copied files under AO-50 so the
// Launcher and Portal share one implementation and can never drift.
//
// No React, no browser dependency: this runs in a server route handler and
// takes a service-role Supabase client plus the incoming request.

export {
  checkAuthEmailRateLimit,
  hashClientIp,
  AUTH_EMAIL_LIMIT,
  AUTH_EMAIL_WINDOW_MS,
  AUTH_IP_LIMIT,
  AUTH_IP_WINDOW_MS,
} from './authEmailRateLimit'
export type { AuthEmailRoute } from './authEmailRateLimit'
