import axios from 'axios'

// [explain] One shared phone line to the backend. Every call starts with /api, and the login cookie is sent automatically (withCredentials).
const api = axios.create({
  baseURL: '/api',
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
})

// [explain] A safety net on every answer: if the server says 401 (the ticket expired), send the user back to the login page.
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
