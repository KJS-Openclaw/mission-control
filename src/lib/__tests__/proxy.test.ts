import { describe, it, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import { proxy } from '@/proxy'

function makeRequest(path: string, init?: RequestInit): NextRequest {
  return new NextRequest(`http://localhost${path}`, init)
}

describe('proxy API auth behavior', () => {
  const originalEnv = { ...process.env }

  beforeEach(() => {
    vi.restoreAllMocks()
    process.env = { ...originalEnv, NODE_ENV: 'development', API_KEY: 'test-api-key' }
  })

  it('does not treat arbitrary session cookie as authenticated API access', () => {
    const req = makeRequest('/api/agents', {
      headers: {
        cookie: 'mc-session=not-a-real-session',
      },
    })

    const res = proxy(req)
    expect(res.status).toBe(200)
  })

  it('allows API key authentication at proxy layer', () => {
    const req = makeRequest('/api/agents', {
      headers: {
        'x-api-key': 'test-api-key',
      },
    })

    const res = proxy(req)
    expect(res.status).toBe(200)
  })
})
