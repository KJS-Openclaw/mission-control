import { createHash } from 'node:crypto'
import { NextRequest, NextResponse } from 'next/server'
import { requireRole } from '@/lib/auth'
import { logAuditEvent } from '@/lib/db'
import { config } from '@/lib/config'
import { join } from 'path'
import { validateBody, gatewayConfigPatchSchema, validateGatewayConfigValue } from '@/lib/validation'
import { mutationLimiter } from '@/lib/rate-limit'

function getConfigPath(): string | null {
  if (!config.openclawHome) return null
  return join(config.openclawHome, 'openclaw.json')
}

const HIGH_RISK_PATHS = new Set(['gateway.host', 'gateway.port', 'gateway.auth.username', 'gateway.auth.enabled'])

function setNestedValue(obj: any, path: string, value: any) {
  const keys = path.split('.')
  let current = obj
  for (let i = 0; i < keys.length - 1; i++) {
    if (current[keys[i]] === undefined) current[keys[i]] = {}
    current = current[keys[i]]
  }
  current[keys[keys.length - 1]] = value
}

function getNestedValue(obj: any, path: string): any {
  return path.split('.').reduce((acc: any, key) => (acc == null ? undefined : acc[key]), obj)
}

function redactValue(path: string, value: unknown): unknown {
  if (/(password|secret|token|key)/i.test(path)) return '••••••••'
  return value
}

function computeConfirmToken(updates: Record<string, unknown>): string {
  const payload = JSON.stringify(Object.entries(updates).sort(([a], [b]) => a.localeCompare(b)))
  return createHash('sha256').update(payload).digest('hex').slice(0, 24)
}

export async function GET(request: NextRequest) {
  const auth = requireRole(request, 'admin')
  if ('error' in auth) return NextResponse.json({ error: auth.error }, { status: auth.status })

  const configPath = getConfigPath()
  if (!configPath) return NextResponse.json({ error: 'OPENCLAW_HOME not configured' }, { status: 404 })

  try {
    const { readFile } = await import('node:fs/promises')
    const raw = await readFile(configPath, 'utf-8')
    const parsed = JSON.parse(raw)
    return NextResponse.json({ path: configPath, config: parsed, raw_size: raw.length })
  } catch (err: any) {
    if (err.code === 'ENOENT') return NextResponse.json({ error: 'Config file not found', path: configPath }, { status: 404 })
    return NextResponse.json({ error: `Failed to read config: ${err.message}` }, { status: 500 })
  }
}

export async function PUT(request: NextRequest) {
  const auth = requireRole(request, 'admin')
  if ('error' in auth) return NextResponse.json({ error: auth.error }, { status: auth.status })
  const rateCheck = mutationLimiter(request)
  if (rateCheck) return rateCheck

  const configPath = getConfigPath()
  if (!configPath) return NextResponse.json({ error: 'OPENCLAW_HOME not configured' }, { status: 404 })

  const parsedBody = await validateBody(request, gatewayConfigPatchSchema)
  if ('error' in parsedBody) return parsedBody.error
  const body = parsedBody.data

  const blockedPaths = ['gateway.auth.password', 'gateway.auth.secret']
  for (const key of Object.keys(body.updates) as Array<keyof typeof body.updates>) {
    if (blockedPaths.some((bp) => key.startsWith(bp))) {
      return NextResponse.json({ error: `Cannot modify protected field: ${key}` }, { status: 403 })
    }
    const validation = validateGatewayConfigValue(key as any, body.updates[key] as unknown)
    if (!validation.success) {
      return NextResponse.json({ error: `Invalid value for ${key}` }, { status: 400 })
    }
  }

  const highRiskTouched = Object.keys(body.updates).some((k) => HIGH_RISK_PATHS.has(k))
  const expectedConfirmToken = computeConfirmToken(body.updates)
  if (highRiskTouched && body.confirmToken !== expectedConfirmToken) {
    return NextResponse.json({
      error: 'High-risk config update requires confirmation',
      requiresConfirmation: true,
      confirmToken: expectedConfirmToken,
    }, { status: 409 })
  }

  const { readFile, writeFile } = await import('node:fs/promises')
  try {
    const raw = await readFile(configPath, 'utf-8')
    const current = JSON.parse(raw)
    const next = JSON.parse(JSON.stringify(current))

    const diff: Array<{ key: string; before: unknown; after: unknown }> = []
    for (const [dotPath, value] of Object.entries(body.updates)) {
      const before = getNestedValue(current, dotPath)
      setNestedValue(next, dotPath, value)
      diff.push({ key: dotPath, before: redactValue(dotPath, before), after: redactValue(dotPath, value) })
    }

    const dryRun = request.nextUrl.searchParams.get('dryRun') === '1'
    if (dryRun) {
      return NextResponse.json({ dryRun: true, diff, count: diff.length })
    }

    await writeFile(configPath, JSON.stringify(next, null, 2) + '\n')

    const ipAddress = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
    logAuditEvent({
      action: 'gateway_config_update',
      actor: auth.user.username,
      actor_id: auth.user.id,
      detail: { diff },
      ip_address: ipAddress,
    })

    return NextResponse.json({ updated: diff.map((d) => d.key), count: diff.length, diff })
  } catch (err: any) {
    return NextResponse.json({ error: `Failed to update config: ${err.message}` }, { status: 500 })
  }
}
