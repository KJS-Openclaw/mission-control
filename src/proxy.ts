import { randomBytes } from 'node:crypto'
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { getApiRoutePolicy, getRequiredScopeForRequest, roleSatisfies } from '@/lib/route-policy'
import { authenticateScopedApiToken, tokenHasScope, validateSession } from '@/lib/auth'

function envFlag(name: string): boolean {
  const raw = process.env[name]
  if (raw === undefined) return false
  const v = String(raw).trim().toLowerCase()
  return v === '1' || v === 'true' || v === 'yes' || v === 'on'
}

function getRequestHostname(request: NextRequest): string {
  const raw = request.headers.get('x-forwarded-host') || request.headers.get('host') || ''
  // If multiple hosts are present, take the first (proxy chain).
  const first = raw.split(',')[0] || ''
  return first.trim().split(':')[0] || ''
}

function hostMatches(pattern: string, hostname: string): boolean {
  const p = pattern.trim().toLowerCase()
  const h = hostname.trim().toLowerCase()
  if (!p || !h) return false

  // "*.example.com" matches "a.example.com" (but not bare "example.com")
  if (p.startsWith('*.')) {
    const suffix = p.slice(2)
    return h.endsWith(`.${suffix}`)
  }

  // "100.*" matches "100.64.0.1"
  if (p.endsWith('.*')) {
    const prefix = p.slice(0, -1)
    return h.startsWith(prefix)
  }

  return h === p
}

function buildCsp(nonce: string): string {
  const googleEnabled = !!(process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID || process.env.GOOGLE_CLIENT_ID)
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'${googleEnabled ? ' https://accounts.google.com' : ''}`,
    `style-src 'self' 'nonce-${nonce}'`,
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "object-src 'none'",
    "connect-src 'self' ws: wss: http://127.0.0.1:* http://localhost:*",
    `img-src 'self' data: blob:${googleEnabled ? ' https://*.googleusercontent.com https://lh3.googleusercontent.com' : ''}`,
    "font-src 'self' data:",
    `frame-src 'self'${googleEnabled ? ' https://accounts.google.com' : ''}`,
  ].join('; ')
}

function applySecurityHeaders(response: NextResponse, nonce: string): NextResponse {
  response.headers.set('X-Content-Type-Options', 'nosniff')
  response.headers.set('X-Frame-Options', 'DENY')
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  response.headers.set('x-mc-csp-nonce', nonce)
  const csp = buildCsp(nonce)
  const enforce = String(process.env.MC_CSP_ENFORCE || '').trim() === '1'
  response.headers.set(enforce ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only', csp)
  return response
}

export function proxy(request: NextRequest) {
  // Network access control.
  // In production: default-deny unless explicitly allowed.
  // In dev/test: allow all hosts unless overridden.
  const hostName = getRequestHostname(request)
  const allowAnyHost = envFlag('MC_ALLOW_ANY_HOST') || process.env.NODE_ENV !== 'production'
  const allowedPatterns = String(process.env.MC_ALLOWED_HOSTS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

  const isAllowedHost = allowAnyHost || allowedPatterns.some((p) => hostMatches(p, hostName))

  if (!isAllowedHost) {
    return new NextResponse('Forbidden', { status: 403 })
  }

  const { pathname } = request.nextUrl
  const cspNonce = randomBytes(16).toString('base64')

  // CSRF Origin validation for mutating requests
  const method = request.method.toUpperCase()
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    const origin = request.headers.get('origin')
    if (origin) {
      let originHost: string
      try { originHost = new URL(origin).host } catch { originHost = '' }
      const requestHost = request.headers.get('host')?.split(',')[0]?.trim()
        || request.nextUrl.host
        || ''
      if (originHost && requestHost && originHost !== requestHost) {
        return applySecurityHeaders(NextResponse.json({ error: 'CSRF origin mismatch' }, { status: 403 }), cspNonce)
      }
    }
  }

  // Allow public pages without session
  if (pathname === '/login' || pathname === '/docs') {
    return applySecurityHeaders(NextResponse.next(), cspNonce)
  }

  // Check for session cookie
  const sessionToken = request.cookies.get('mc-session')?.value

  if (pathname.startsWith('/api/')) {
    const policy = getApiRoutePolicy(pathname)
    if (!policy) {
      return applySecurityHeaders(NextResponse.json({ error: 'Forbidden' }, { status: 403 }), cspNonce)
    }

    if (policy.access === 'public') {
      return applySecurityHeaders(NextResponse.next(), cspNonce)
    }

    if (sessionToken) {
      const sessionUser = validateSession(sessionToken)
      if (sessionUser && roleSatisfies(sessionUser.role, policy.access)) {
        return applySecurityHeaders(NextResponse.next(), cspNonce)
      }
    }

    const apiKey = request.headers.get('x-api-key')
    if (policy.apiKeyAllowed && apiKey) {
      const token = authenticateScopedApiToken(apiKey)
      if (token && roleSatisfies(token.role, policy.access)) {
        const requiredScope = getRequiredScopeForRequest(pathname, method)
        if (tokenHasScope(token.scopes, requiredScope)) {
          return applySecurityHeaders(NextResponse.next(), cspNonce)
        }
      }
    }

    return applySecurityHeaders(NextResponse.json({ error: 'Forbidden' }, { status: 403 }), cspNonce)
  }

  // Page routes: redirect to login if no session
  if (sessionToken) {
    return applySecurityHeaders(NextResponse.next(), cspNonce)
  }

  // Redirect to login
  const loginUrl = request.nextUrl.clone()
  loginUrl.pathname = '/login'
  return NextResponse.redirect(loginUrl)
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)']
}
