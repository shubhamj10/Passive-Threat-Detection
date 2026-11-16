// REST client. In development Vite proxies /api and /ws to the backend on :8000.
async function request(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    let detail = res.statusText
    try { detail = (await res.json()).detail ?? detail } catch { /* not JSON */ }
    throw new Error(`${res.status}: ${detail}`)
  }
  return res.json()
}

const post = (path, body) => request(path, { method: 'POST', body: body ? JSON.stringify(body) : undefined })

export const api = {
  health: () => request('/api/health'),
  alerts: (params = {}) => request(`/api/alerts?${new URLSearchParams(params)}`),
  alert: (id) => request(`/api/alerts/${encodeURIComponent(id)}`),
  feedback: (id, verdict, note) => post(`/api/alerts/${encodeURIComponent(id)}/feedback`, { verdict, note }),
  replayAlert: (id) => post(`/api/alerts/${encodeURIComponent(id)}/replay`),
  explain: (id) => post(`/api/alerts/${encodeURIComponent(id)}/explain`),
  stats: () => request('/api/stats'),
  assuranceStatus: () => request('/api/assurance/status'),
  assuranceAlerts: () => request('/api/assurance/alerts'),
  replayStart: (file) => post('/api/replay/start', file ? { file } : {}),
  replayPause: () => post('/api/replay/pause'),
  replaySpeed: (speed) => post('/api/replay/speed', { speed }),
  replayStatus: () => request('/api/replay/status'),
  replayFiles: () => request('/api/replay/files'),
}

export function wsUrl(path = '/ws/alerts') {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${window.location.host}${path}`
}
