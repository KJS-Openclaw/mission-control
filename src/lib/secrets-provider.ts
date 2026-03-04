import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { config } from '@/lib/config'
import { getDatabase } from '@/lib/db'

export interface SecretMetadata {
  key: string
  backend: 'env-file' | 'onepassword'
  lastRotatedAt: number | null
}

interface EnvLine {
  type: 'comment' | 'blank' | 'var'
  raw: string
  key?: string
  value?: string
}

function parseEnv(content: string): EnvLine[] {
  return content.split('\n').map((raw) => {
    const trimmed = raw.trim()
    if (!trimmed) return { type: 'blank', raw }
    if (trimmed.startsWith('#')) return { type: 'comment', raw }
    const eq = raw.indexOf('=')
    if (eq <= 0) return { type: 'comment', raw }
    const key = raw.slice(0, eq).trim()
    const value = raw.slice(eq + 1)
    return { type: 'var', raw, key, value }
  })
}

function serializeEnv(lines: EnvLine[]): string {
  return lines.map((l) => (l.type === 'var' ? `${l.key}=${l.value}` : l.raw)).join('\n')
}

function getEnvPath(): string | null {
  if (!config.openclawHome) return null
  return join(config.openclawHome, '.env')
}

function getSecretsKey(): Buffer | null {
  const keyFile = process.env.MC_SECRETS_KEY_FILE
  if (!keyFile || !existsSync(keyFile)) return null
  const material = readFileSync(keyFile, 'utf-8').trim()
  if (!material) return null
  return createHash('sha256').update(material).digest()
}

function encryptIfNeeded(value: string): string {
  const key = getSecretsKey()
  if (!key) return value
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return `ENC[v1]:${iv.toString('base64')}:${encrypted.toString('base64')}:${tag.toString('base64')}`
}

function decryptIfNeeded(value: string): string {
  if (!value.startsWith('ENC[v1]:')) return value
  const key = getSecretsKey()
  if (!key) return ''
  const [, ivB64, dataB64, tagB64] = value.split(':')
  if (!ivB64 || !dataB64 || !tagB64) return ''
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'))
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'))
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(dataB64, 'base64')),
      decipher.final(),
    ])
    return decrypted.toString('utf8')
  } catch {
    return ''
  }
}

export async function setSecrets(input: {
  workspaceId: number
  values: Record<string, string>
  updatedBy?: number
}): Promise<string[]> {
  const envPath = getEnvPath()
  if (!envPath) throw new Error('OPENCLAW_HOME not configured')

  const fs = await import('node:fs/promises')
  let raw = ''
  try { raw = await fs.readFile(envPath, 'utf-8') } catch {}
  const lines = parseEnv(raw)

  const updatedKeys: string[] = []
  for (const [key, val] of Object.entries(input.values)) {
    const encrypted = encryptIfNeeded(String(val))
    const existing = lines.find((line) => line.type === 'var' && line.key === key)
    if (existing) existing.value = encrypted
    else lines.push({ type: 'var', raw: '', key, value: encrypted })
    updatedKeys.push(key)
  }

  await fs.writeFile(envPath, serializeEnv(lines), 'utf-8')

  const db = getDatabase()
  const now = Math.floor(Date.now() / 1000)
  const stmt = db.prepare(`
    INSERT INTO integration_secrets (workspace_id, secret_key, backend, last_rotated_at, updated_by, created_at, updated_at)
    VALUES (?, ?, 'env-file', ?, ?, ?, ?)
    ON CONFLICT(workspace_id, secret_key) DO UPDATE SET
      backend = 'env-file',
      last_rotated_at = excluded.last_rotated_at,
      updated_by = excluded.updated_by,
      updated_at = excluded.updated_at
  `)
  for (const key of updatedKeys) {
    stmt.run(input.workspaceId, key, now, input.updatedBy ?? null, now, now)
  }

  return updatedKeys
}

export async function removeSecrets(input: { workspaceId: number; keys: string[]; updatedBy?: number }): Promise<string[]> {
  const envPath = getEnvPath()
  if (!envPath) throw new Error('OPENCLAW_HOME not configured')
  const fs = await import('node:fs/promises')
  let raw = ''
  try { raw = await fs.readFile(envPath, 'utf-8') } catch {}
  const lines = parseEnv(raw)
  const keys = new Set(input.keys)
  const removed: string[] = []
  const nextLines = lines.filter((line) => {
    if (line.type === 'var' && line.key && keys.has(line.key)) {
      removed.push(line.key)
      return false
    }
    return true
  })
  await fs.writeFile(envPath, serializeEnv(nextLines), 'utf-8')
  return removed
}

export async function listSecretsMetadata(workspaceId: number): Promise<SecretMetadata[]> {
  const db = getDatabase()
  const rows = db.prepare(`
    SELECT secret_key, backend, last_rotated_at
    FROM integration_secrets
    WHERE workspace_id = ?
    ORDER BY secret_key ASC
  `).all(workspaceId) as Array<{ secret_key: string; backend: 'env-file' | 'onepassword'; last_rotated_at: number | null }>
  return rows.map((r) => ({ key: r.secret_key, backend: r.backend, lastRotatedAt: r.last_rotated_at }))
}

export async function getSecretValue(key: string): Promise<string | null> {
  const envPath = getEnvPath()
  if (!envPath) return null
  const fs = await import('node:fs/promises')
  let raw = ''
  try { raw = await fs.readFile(envPath, 'utf-8') } catch { return null }
  for (const line of parseEnv(raw)) {
    if (line.type === 'var' && line.key === key) return decryptIfNeeded(line.value || '')
  }
  return null
}
