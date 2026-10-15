import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Double-submit CSRF: repeat the csrf_token cookie in a header on every call that changes something.
api.interceptors.request.use((config) => {
  const method = (config.method || 'get').toLowerCase()
  if (!['get', 'head', 'options'].includes(method)) {
    const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/)
    if (match) config.headers.set('X-CSRF-Token', decodeURIComponent(match[1]))
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Only redirect to /login on 401 if we're NOT already on /login
    // (otherwise we get an infinite loop when fetchUser() fails on the login page)
    if (error.response?.status === 401) {
      const currentPath = window.location.pathname
      if (currentPath !== '/login') {
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

export default api
