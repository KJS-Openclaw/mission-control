import { NextResponse } from 'next/server'
import {
  createScopedApiToken,
  listScopedApiTokens,
  requireRole,
  revokeScopedApiToken,
} from '@/lib/auth'
import { logAuditEvent } from '@/lib/db'
import { validateBody } from '@/lib/validation'
import { z } from 'zod'

const createTokenSchema = z.object({
  name: z.string().min(1).max(120),
  role: z.enum(['admin', 'operator', 'viewer']).default('viewer'),
  scopes: z.array(z.string()).default(['read:*']),
  expiresAt: z.number().int().positive().nullable().optional(),
})

const revokeTokenSchema = z.object({
  id: z.number().int().positive(),
})

export async function GET(request: Request) {
  const auth = requireRole(request, 'admin')
  if ('error' in auth) return NextResponse.json({ error: auth.error }, { status: auth.status })

  const tokens = listScopedApiTokens(auth.user.workspace_id).map((token) => ({
    ...token,
    token_hash: undefined,
  }))
  return NextResponse.json({ tokens })
}

export async function POST(request: Request) {
  const auth = requireRole(request, 'admin')
  if ('error' in auth) return NextResponse.json({ error: auth.error }, { status: auth.status })

  const parsed = await validateBody(request, createTokenSchema)
  if ('error' in parsed) return parsed.error

  const created = createScopedApiToken({
    workspaceId: auth.user.workspace_id,
    name: parsed.data.name,
    role: parsed.data.role,
    scopes: parsed.data.scopes,
    expiresAt: parsed.data.expiresAt,
    createdBy: auth.user.id,
  })

  logAuditEvent({
    action: 'api_token_created',
    actor: auth.user.username,
    actor_id: auth.user.id,
    detail: {
      token_id: created.record.id,
      name: created.record.name,
      role: created.record.role,
      scopes: created.record.scopes,
      expires_at: created.record.expires_at,
    },
  })

  return NextResponse.json({
    token: created.token,
    record: created.record,
  }, { status: 201 })
}

export async function DELETE(request: Request) {
  const auth = requireRole(request, 'admin')
  if ('error' in auth) return NextResponse.json({ error: auth.error }, { status: auth.status })

  const parsed = await validateBody(request, revokeTokenSchema)
  if ('error' in parsed) return parsed.error

  const revoked = revokeScopedApiToken(auth.user.workspace_id, parsed.data.id)
  if (!revoked) {
    return NextResponse.json({ error: 'Token not found or already revoked' }, { status: 404 })
  }

  logAuditEvent({
    action: 'api_token_revoked',
    actor: auth.user.username,
    actor_id: auth.user.id,
    detail: { token_id: parsed.data.id },
  })

  return NextResponse.json({ ok: true, revokedId: parsed.data.id })
}
