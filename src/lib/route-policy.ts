export type RouteRole = 'viewer' | 'operator' | 'admin'

export interface RoutePolicy {
  access: 'public' | RouteRole
  apiKeyAllowed: boolean
}

export const API_ROUTE_POLICIES: Record<string, RoutePolicy> = {
  '/api/activities': { access: 'viewer', apiKeyAllowed: true },
  '/api/agents': { access: 'viewer', apiKeyAllowed: true },
  '/api/agents/[id]': { access: 'viewer', apiKeyAllowed: true },
  '/api/agents/[id]/heartbeat': { access: 'viewer', apiKeyAllowed: true },
  '/api/agents/[id]/memory': { access: 'viewer', apiKeyAllowed: true },
  '/api/agents/[id]/soul': { access: 'viewer', apiKeyAllowed: true },
  '/api/agents/[id]/wake': { access: 'operator', apiKeyAllowed: true },
  '/api/agents/comms': { access: 'viewer', apiKeyAllowed: true },
  '/api/agents/message': { access: 'operator', apiKeyAllowed: true },
  '/api/agents/sync': { access: 'admin', apiKeyAllowed: true },
  '/api/alerts': { access: 'viewer', apiKeyAllowed: true },
  '/api/audit': { access: 'admin', apiKeyAllowed: true },
  '/api/auth/access-requests': { access: 'viewer', apiKeyAllowed: false },
  '/api/auth/google': { access: 'public', apiKeyAllowed: false },
  '/api/auth/login': { access: 'public', apiKeyAllowed: false },
  '/api/auth/logout': { access: 'public', apiKeyAllowed: false },
  '/api/auth/me': { access: 'viewer', apiKeyAllowed: false },
  '/api/auth/tokens': { access: 'admin', apiKeyAllowed: false },
  '/api/auth/users': { access: 'viewer', apiKeyAllowed: false },
  '/api/backup': { access: 'admin', apiKeyAllowed: true },
  '/api/chat/conversations': { access: 'viewer', apiKeyAllowed: true },
  '/api/chat/messages': { access: 'viewer', apiKeyAllowed: true },
  '/api/chat/messages/[id]': { access: 'viewer', apiKeyAllowed: true },
  '/api/claude/sessions': { access: 'viewer', apiKeyAllowed: true },
  '/api/cleanup': { access: 'admin', apiKeyAllowed: true },
  '/api/connect': { access: 'viewer', apiKeyAllowed: true },
  '/api/cron': { access: 'admin', apiKeyAllowed: true },
  '/api/docs': { access: 'public', apiKeyAllowed: false },
  '/api/events': { access: 'viewer', apiKeyAllowed: true },
  '/api/export': { access: 'admin', apiKeyAllowed: true },
  '/api/gateway-config': { access: 'admin', apiKeyAllowed: true },
  '/api/gateways': { access: 'viewer', apiKeyAllowed: true },
  '/api/gateways/health': { access: 'viewer', apiKeyAllowed: true },
  '/api/github': { access: 'operator', apiKeyAllowed: true },
  '/api/integrations': { access: 'admin', apiKeyAllowed: true },
  '/api/logs': { access: 'viewer', apiKeyAllowed: true },
  '/api/memory': { access: 'viewer', apiKeyAllowed: true },
  '/api/notifications': { access: 'viewer', apiKeyAllowed: true },
  '/api/notifications/deliver': { access: 'viewer', apiKeyAllowed: true },
  '/api/pipelines': { access: 'viewer', apiKeyAllowed: true },
  '/api/pipelines/run': { access: 'viewer', apiKeyAllowed: true },
  '/api/quality-review': { access: 'viewer', apiKeyAllowed: true },
  '/api/releases/check': { access: 'public', apiKeyAllowed: false },
  '/api/scheduler': { access: 'admin', apiKeyAllowed: true },
  '/api/search': { access: 'viewer', apiKeyAllowed: true },
  '/api/sessions': { access: 'viewer', apiKeyAllowed: true },
  '/api/sessions/[id]/control': { access: 'operator', apiKeyAllowed: true },
  '/api/settings': { access: 'admin', apiKeyAllowed: true },
  '/api/spawn': { access: 'viewer', apiKeyAllowed: true },
  '/api/standup': { access: 'viewer', apiKeyAllowed: true },
  '/api/status': { access: 'viewer', apiKeyAllowed: true },
  '/api/super/provision-jobs': { access: 'admin', apiKeyAllowed: true },
  '/api/super/provision-jobs/[id]': { access: 'admin', apiKeyAllowed: true },
  '/api/super/provision-jobs/[id]/run': { access: 'admin', apiKeyAllowed: true },
  '/api/super/tenants': { access: 'admin', apiKeyAllowed: true },
  '/api/super/tenants/[id]/decommission': { access: 'admin', apiKeyAllowed: true },
  '/api/tasks': { access: 'viewer', apiKeyAllowed: true },
  '/api/tasks/[id]': { access: 'viewer', apiKeyAllowed: true },
  '/api/tasks/[id]/broadcast': { access: 'operator', apiKeyAllowed: true },
  '/api/tasks/[id]/comments': { access: 'viewer', apiKeyAllowed: true },
  '/api/tokens': { access: 'viewer', apiKeyAllowed: true },
  '/api/webhooks': { access: 'admin', apiKeyAllowed: true },
  '/api/webhooks/deliveries': { access: 'admin', apiKeyAllowed: true },
  '/api/webhooks/retry': { access: 'admin', apiKeyAllowed: true },
  '/api/webhooks/test': { access: 'admin', apiKeyAllowed: true },
  '/api/webhooks/verify-docs': { access: 'viewer', apiKeyAllowed: true },
  '/api/workflows': { access: 'viewer', apiKeyAllowed: true },
}

const ROLE_LEVELS: Record<RouteRole, number> = { viewer: 0, operator: 1, admin: 2 }

function toPatternRegExp(pattern: string): RegExp {
  const escaped = pattern
    .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\\\[\\\.\\\.\\\.([^\]]+)\\\]/g, '(.+)')
    .replace(/\\\[\\\[\\\.\\\.\\\.([^\]]+)\\\]\\\]/g, '(.*)')
    .replace(/\\\[([^\]]+)\\\]/g, '([^/]+)')
  return new RegExp(`^${escaped}$`)
}

export function getApiRoutePolicy(pathname: string): RoutePolicy | null {
  for (const [pattern, policy] of Object.entries(API_ROUTE_POLICIES)) {
    if (toPatternRegExp(pattern).test(pathname)) {
      return policy
    }
  }
  return null
}

export function roleSatisfies(actualRole: RouteRole, requiredRole: RouteRole): boolean {
  return ROLE_LEVELS[actualRole] >= ROLE_LEVELS[requiredRole]
}


export function getRequiredScopeForRequest(pathname: string, method: string): string {
  const upper = method.toUpperCase()
  if (upper === 'GET' || upper === 'HEAD' || upper === 'OPTIONS') return 'read:*'

  if (pathname.startsWith('/api/tasks')) return 'tasks:write'
  if (pathname.startsWith('/api/agents')) return 'agents:write'
  if (pathname.startsWith('/api/gateway-config')) return 'config:write'
  if (pathname.startsWith('/api/integrations')) return 'integrations:write'

  return 'read:*'
}
