// ---------------------------------------------------------------------------
// vulnforge console — API client
// Reads the API base from `VITE_API_BASE` (fallback: /api), attaches the bearer
// token stored in localStorage by the Settings page.
// ---------------------------------------------------------------------------

const STORAGE_KEYS = {
  apiBase: 'vulnforge.apiBase',
  token: 'vulnforge.token',
}

export function getApiBase() {
  return localStorage.getItem(STORAGE_KEYS.apiBase) ||
    import.meta.env.VITE_API_BASE ||
    '/api'
}

export function getToken() {
  return localStorage.getItem(STORAGE_KEYS.token) || ''
}

export function setApiBase(base) {
  if (base) {
    localStorage.setItem(STORAGE_KEYS.apiBase, base)
  } else {
    localStorage.removeItem(STORAGE_KEYS.apiBase)
  }
}

export function setToken(token) {
  if (token) {
    localStorage.setItem(STORAGE_KEYS.token, token)
  } else {
    localStorage.removeItem(STORAGE_KEYS.token)
  }
}

function normalizeBase(base) {
  return base.replace(/\/+$/, '')
}

async function request(path, options = {}) {
  const base = normalizeBase(getApiBase())
  const token = getToken()

  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const response = await fetch(`${base}${path}`, {
    ...options,
    headers,
  })

  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`
    try {
      const body = await response.json()
      if (body && body.detail) {
        detail = typeof body.detail === 'string'
          ? body.detail
          : JSON.stringify(body.detail)
      }
    } catch {
      // ignore non-JSON error bodies
    }
    const error = new Error(detail)
    error.status = response.status
    throw error
  }

  if (response.status === 204) {
    return null
  }
  return response.json()
}

export const api = {
  get: (path) => request(path),
  post: (path, body) => request(path, {
    method: 'POST',
    body: JSON.stringify(body),
  }),
  put: (path, body) => request(path, {
    method: 'PUT',
    body: JSON.stringify(body),
  }),
  del: (path) => request(path, { method: 'DELETE' }),
}

// --- Typed helpers ---------------------------------------------------------

export const health = () => api.get('/health')

export const getStats = () => api.get('/stats')

export const getScans = () => api.get('/scans')

export const getScan = (id) => api.get(`/scans/${id}`)

export const createScan = (payload) => api.post('/scans', payload)

export const cancelScan = (id) => api.post(`/scans/${id}/cancel`)

export const getFindings = (params) => {
  const qs = new URLSearchParams()
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') {
        qs.set(key, value)
      }
    })
  }
  const query = qs.toString()
  return api.get(`/findings${query ? `?${query}` : ''}`)
}

export const getFinding = (id) => api.get(`/findings/${id}`)

export const getRules = () => api.get('/rules')

export const getProviders = () => api.get('/providers')
