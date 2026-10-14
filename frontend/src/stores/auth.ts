import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import api from '@/api/client'

interface User {
  id: string
  email: string
  full_name: string
  role: 'admin' | 'soc_l1' | 'soc_l2' | 'soc_l3'
  is_active: boolean
  created_at: string
}

// [explain] The browser's memory of who is logged in. Every page can read it, so the menu and buttons match the user's role.
// [explain] The real permission checks are on the server; hiding a button here is only for comfort.
export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const loading = ref(false)
  const checked = ref(false)

  const isAuthenticated = computed(() => !!user.value)
  const role = computed(() => user.value?.role)
  const isAdmin = computed(() => role.value === 'admin')
  const isL2Plus = computed(() => ['soc_l2', 'soc_l3', 'admin'].includes(role.value || ''))

  // [explain] Send the credentials; on success the server sets the cookies and we load who we are.
  async function login(email: string, password: string) {
    loading.value = true
    try {
      await api.post('/auth/login', { email, password })
      await fetchUser()
    } finally {
      loading.value = false
    }
  }

  // [explain] Ask "who am I?". No answer means nobody is logged in.
  async function fetchUser() {
    try {
      const { data } = await api.get('/auth/me')
      user.value = data
    } catch (e) {
      user.value = null
    } finally {
      checked.value = true
    }
  }

  // [explain] Tell the server to clear the cookies, forget the user here, and go to the login page.
  async function logout() {
    try {
      await api.post('/auth/logout')
    } catch (e) {
      // ignore
    }
    user.value = null
    checked.value = true
    window.location.href = '/login'
  }

  return { user, loading, checked, isAuthenticated, role, isAdmin, isL2Plus, login, fetchUser, logout }
})
