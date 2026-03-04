import { describe, it, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import { proxy } from '@/proxy'

function makeRequest(path: string, init?: ConstructorParameters<typeof NextRequest>[1]): NextRequest {
  return new NextRequest(`http://localhost${path}`, init)
}

describe('proxy API auth behavior', () => {
  const originalEnv = { ...process.env }

  beforeEach(() => {
    vi.restoreAllMocks()
    process.env = { ...originalEnv, NODE_ENV: 'development', API_KEY: 'test-api-key', MC_LEGACY_API_KEY: '1' }
  })

  it('denies unknown API routes (default-deny)', () => {
    const req = makeRequest('/api/unknown-route')
    const res = proxy(req)
    expect(res.status).toBe(403)
  })

  it('allows public API route without auth', () => {
    const req = makeRequest('/api/docs')
    const res = proxy(req)
    expect(res.status).toBe(200)
  })

  it('allows API key authentication only for apiKeyAllowed routes', () => {
    const req = makeRequest('/api/agents', {
      headers: {
        'x-api-key': 'test-api-key',
      },
    })

    const res = proxy(req)
    expect(res.status).toBe(200)
  })

  it('blocks API key auth on routes that disallow api keys', () => {
    const req = makeRequest('/api/auth/users', {
      headers: {
        'x-api-key': 'test-api-key',
      },
    })

    const res = proxy(req)
    expect(res.status).toBe(403)
  })
})
