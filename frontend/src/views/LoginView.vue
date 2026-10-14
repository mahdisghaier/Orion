<template>
  <div class="min-h-screen flex items-center justify-center bg-[#0a1628]">
    <div class="w-full max-w-md p-8 bg-white/5 backdrop-blur rounded-lg border border-[#4da8da]/30">
      <div class="text-center mb-8">
        <h1 class="text-4xl font-black text-[#e8f0f8] tracking-tight">ORION</h1>
        <p class="text-[#7a9bb8] mt-2 text-sm">Federated Multi-SIEM AI Threat Hunting Platform</p>
      </div>
      <form @submit.prevent="handleLogin" class="space-y-4">
        <div>
          <label for="email" class="block text-xs uppercase tracking-wider text-[#7a9bb8] mb-2">Email</label>
          <input
            id="email"
            v-model="email"
            type="email"
            required
            class="w-full px-3 py-2 bg-transparent border border-[#4da8da]/30 text-[#e8f0f8] rounded focus:outline-none focus:border-[#4da8da]"
            placeholder="you@example.com"
          />
        </div>
        <div>
          <label for="password" class="block text-xs uppercase tracking-wider text-[#7a9bb8] mb-2">Password</label>
          <input
            id="password"
            v-model="password"
            type="password"
            required
            class="w-full px-3 py-2 bg-transparent border border-[#4da8da]/30 text-[#e8f0f8] rounded focus:outline-none focus:border-[#4da8da]"
            placeholder="••••••••"
          />
        </div>
        <div v-if="error" class="text-red-400 text-sm">{{ error }}</div>
        <button
          type="submit"
          :disabled="auth.loading"
          class="w-full py-2 bg-[#2d7ab3] hover:bg-[#4da8da] text-white rounded transition-colors disabled:opacity-50"
        >
          {{ auth.loading ? 'Signing in...' : 'Sign In' }}
        </button>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const router = useRouter()

const email = ref('')
const password = ref('')
const error = ref('')

async function handleLogin() {
  error.value = ''
  try {
    console.log('[LoginView] handleLogin starting')
    await auth.login(email.value, password.value)
    console.log('[LoginView] auth.login done, user =', auth.user)
    console.log('[LoginView] pushing to /findings')
    router.push('/findings')
    console.log('[LoginView] router.push done')
  } catch (e: any) {
    console.error('[LoginView] login error:', e)
    error.value = e.response?.data?.detail?.[0]?.msg || e.response?.data?.detail || 'Login failed'
  }
}
</script>
