#!/usr/bin/env node
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'

const repoRoot = process.cwd()
const apiRoot = join(repoRoot, 'src', 'app', 'api')
const policyFile = join(repoRoot, 'src', 'lib', 'route-policy.ts')

function walk(dir) {
  const out = []
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    const st = statSync(full)
    if (st.isDirectory()) {
      out.push(...walk(full))
    } else if (entry === 'route.ts') {
      out.push(full)
    }
  }
  return out
}

function routePathFromFile(file) {
  const rel = relative(apiRoot, file)
  return `/api/${rel.split(sep).slice(0, -1).join('/')}`
}

const routes = walk(apiRoot).map(routePathFromFile).sort()
const policyText = readFileSync(policyFile, 'utf-8')
const policyPaths = new Set([...policyText.matchAll(/\s+'(\/api\/[^']+)'\s*:/g)].map((m) => m[1]))

const missing = routes.filter((route) => !policyPaths.has(route))
const orphaned = [...policyPaths].filter((route) => !routes.includes(route)).sort()

if (missing.length || orphaned.length) {
  if (missing.length) {
    console.error('Missing API policy entries for these routes:')
    for (const route of missing) console.error(`  - ${route}`)
  }

  if (orphaned.length) {
    console.error('Route policy entries with no matching route file:')
    for (const route of orphaned) console.error(`  - ${route}`)
  }

  process.exit(1)
}

console.log(`API auth policy coverage check passed (${routes.length} routes).`)
