const defaultBaseUrl = typeof window !== 'undefined' && window.location?.hostname
  ? `${window.location.protocol}//${window.location.hostname}:8000`
  : 'http://localhost:8000'
const baseUrl = import.meta.env.VITE_API_BASE_URL || defaultBaseUrl

async function request(path, options = {}) {
  const controller = new AbortController()
  const timeout = window.setTimeout(() => controller.abort(), options.timeout || 8000)
  try {
    const response = await fetch(`${baseUrl}${path}`, {
      ...options,
      headers: {
        ...(options.body ? { 'Content-Type': 'application/json' } : {}),
        ...(localStorage.getItem('cyber14_access_token') ? { Authorization: `Bearer ${localStorage.getItem('cyber14_access_token')}` } : {}),
        ...(options.headers || {}),
      },
      signal: controller.signal,
    })
    const body = await response.json().catch(() => null)
    if (!response.ok) {
      if (response.status === 401) {
        localStorage.removeItem('cyber14_access_token')
        window.dispatchEvent(new Event('cyber14:auth-expired'))
      }
      const error = new Error(body?.detail || body?.message || `Request failed with ${response.status}`)
      error.status = response.status
      throw error
    }
    return body
  } finally {
    window.clearTimeout(timeout)
  }
}

export const api = {
  baseUrl,
  health: () => request('/health'),
  status: (opts = {}) => request('/api/v1/system/status', { timeout: 30000, ...opts }),
  analyze: (payload) => request('/api/v1/detection/analyze', { method: 'POST', body: JSON.stringify(payload) }),
  simulate: (payload) => request('/api/v1/stream/simulate', { method: 'POST', body: JSON.stringify(payload) }),
  login: (payload) => request('/api/v1/auth/login', { method: 'POST', body: JSON.stringify(payload) }),
  me: () => request('/api/v1/auth/me'),
  logout: () => request('/api/v1/auth/logout', { method: 'POST' }),
  telemetry: (opts = {}) => request('/api/v1/system/telemetry', { timeout: 30000, ...opts }),
  evidenceSummary: () => request('/api/v1/evidence/summary'),
  evidenceRuns: () => request('/api/v1/evidence/runs'),
  audit: (params = '') => request(`/api/v1/evidence/audit${params}`),
  kpis: () => request('/api/v1/evaluation/kpis'),
  acceptance: () => request('/api/v1/evaluation/acceptance'),
  negativeTests: () => request('/api/v1/evaluation/negative-tests'),
  demoScenarios: () => request('/api/v1/detection/demo-scenarios'),
  demoManifest: () => request('/api/v1/evidence/demo-manifest'),
  demoEvaluation: () => request('/api/v1/evidence/demo-evaluation'),
  featureManifest: () => request('/api/v1/evidence/feature-manifest'),
  databaseStatus: () => request('/api/v1/system/database'),
  detectionHistory: (params = '') => request(`/api/v1/detections/history${params}`),
  incidents: (params = '') => request(`/api/v1/incidents${params}`),
  incidentDetail: (id) => request(`/api/v1/incidents/${id}`),
  mitigationHistory: (params = '') => request(`/api/v1/mitigation/history${params}`),
  auditLogs: (params = '') => request(`/api/v1/audit/logs${params}`),
  liveAnalytics: () => request('/api/v1/analytics/live'),
}

export function websocketUrl(token = localStorage.getItem('cyber14_access_token')) {
  const url = new URL(baseUrl)
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  url.pathname = '/ws/traffic'
  if (token) url.searchParams.set('access_token', token)
  return url.toString()
}
