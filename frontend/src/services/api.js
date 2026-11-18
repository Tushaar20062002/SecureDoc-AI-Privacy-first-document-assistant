import axios from 'axios'

// All requests go to the same origin (Vite proxy in dev). Session cookie is HttpOnly;
// the CSRF token is echoed back in a header for state-changing requests.
let csrfToken = null

export function setCsrfToken(token) {
  csrfToken = token || null
}

function csrfFromCookie() {
  const m = document.cookie.match(/(?:^|;\s*)sd_csrf=([^;]+)/)
  return m ? decodeURIComponent(m[1]) : null
}

const api = axios.create({ baseURL: '/api', withCredentials: true, timeout: 120000 })

api.interceptors.request.use((config) => {
  const method = (config.method || 'get').toUpperCase()
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const token = csrfToken || csrfFromCookie()
    if (token) config.headers['X-CSRF-Token'] = token
  }
  return config
})

export function errorMessage(err, fallback = 'Something went wrong. Please try again.') {
  const d = err?.response?.data?.detail
  if (typeof d === 'string') return d
  if (err?.response?.status === 429) return 'Too many requests. Please wait a moment.'
  if (err?.code === 'ECONNABORTED') return 'The request timed out.'
  return fallback
}

export const authApi = {
  me: () => api.get('/auth/me').then((r) => r.data),
  login: (email, password) => api.post('/auth/login', { email, password }).then((r) => r.data),
  register: (email, password) => api.post('/auth/register', { email, password }).then((r) => r.data),
  logout: () => api.post('/auth/logout'),
}

export const privacyApi = {
  policy: () => api.get('/privacy/policy').then((r) => r.data),
  preferences: () => api.get('/privacy/preferences').then((r) => r.data),
  save: (body) => api.put('/privacy/preferences', body).then((r) => r.data),
  consents: () => api.get('/privacy/consents').then((r) => r.data),
  deleteAllDocuments: () => api.delete('/privacy/documents').then((r) => r.data),
}

export const documentsApi = {
  list: () => api.get('/documents').then((r) => r.data),
  get: (id) => api.get(`/documents/${encodeURIComponent(id)}`).then((r) => r.data),
  upload: (file, outputMode, onProgress) => {
    const form = new FormData()
    form.append('file', file)
    form.append('output_mode', outputMode)
    return api
      .post('/documents/upload', form, {
        // AI reading of images can wait for the provider's per-minute token window: allow 10 min.
        timeout: 600000,
        onUploadProgress: (e) => onProgress && e.total && onProgress(Math.round((e.loaded / e.total) * 100)),
      })
      .then((r) => r.data)
  },
  remove: (id) => api.delete(`/documents/${encodeURIComponent(id)}`).then((r) => r.data),
  history: (id) => api.get(`/documents/${encodeURIComponent(id)}/chat/history`).then((r) => r.data),
  chat: (id, message) => api.post(`/documents/${encodeURIComponent(id)}/chat`, { message }).then((r) => r.data),
  pdfUrl: (id) => `/api/documents/${encodeURIComponent(id)}/download/pdf`,
  zipUrl: (ids) => `/api/documents/download/zip?ids=${ids.map(encodeURIComponent).join(',')}`,
  jsonUrl: (id) => `/api/documents/${encodeURIComponent(id)}/download/json`,
}

export default api
