<template>
  <div class="p-8">
    <h1 class="text-2xl font-bold text-[#142840]">Users</h1>
    <p class="text-sm text-gray-500 mt-1 max-w-3xl">
      Accounts and roles. L1 analysts view and run hunts; L2 and above also review, suppress and escalate; L3 concludes incidents;
      administrators manage connections, users and jobs.
    </p>

    <form @submit.prevent="add" class="mt-6 bg-white border rounded-lg p-5 grid grid-cols-1 md:grid-cols-2 gap-3 max-w-3xl">
      <div>
        <label class="block text-xs uppercase text-gray-500 mb-1">Full name</label>
        <input v-model="form.full_name" class="w-full px-3 py-2 border rounded text-sm" />
      </div>
      <div>
        <label class="block text-xs uppercase text-gray-500 mb-1">Email</label>
        <input v-model="form.email" type="email" class="w-full px-3 py-2 border rounded text-sm" />
      </div>
      <div>
        <label class="block text-xs uppercase text-gray-500 mb-1">Role</label>
        <select v-model="form.role" class="w-full px-3 py-2 border rounded text-sm">
          <option value="soc_l1">L1 analyst</option>
          <option value="soc_l2">L2 analyst</option>
          <option value="soc_l3">L3 analyst</option>
          <option value="admin">Administrator</option>
        </select>
      </div>
      <div>
        <label class="block text-xs uppercase text-gray-500 mb-1">Initial password (8 characters or more)</label>
        <input v-model="form.password" type="password" autocomplete="new-password" class="w-full px-3 py-2 border rounded text-sm" />
      </div>
      <div v-if="auth.isPlatform && clients.length > 0">
        <label class="block text-xs uppercase text-gray-500 mb-1">Client</label>
        <select v-model="form.client_id" class="w-full px-3 py-2 border rounded text-sm">
          <option value="">All clients (SOC staff)</option>
          <option v-for="c in clients" :key="c.id" :value="c.id">{{ c.name }}</option>
        </select>
      </div>
      <div class="md:col-span-2 flex items-center gap-3">
        <button :disabled="!canCreate || busy" class="px-4 py-2 bg-[#1a4a7a] text-white rounded text-sm disabled:opacity-50">Create user</button>
        <span v-if="error" class="text-sm text-red-600">{{ error }}</span>
      </div>
    </form>

    <div v-if="loading" class="text-gray-500 py-8">Loading...</div>
    <div v-else-if="loadError" class="py-6">
      <p class="text-red-600 font-medium">Could not load the users.</p>
      <p class="text-sm text-gray-500 mt-1">{{ loadError }}</p>
    </div>
    <div v-else class="mt-6 bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-[#1a4a7a] text-white">
          <tr>
            <th class="text-left px-4 py-3 font-medium">Name</th>
            <th class="text-left px-4 py-3 font-medium">Email</th>
            <th class="text-left px-4 py-3 font-medium">Role</th>
            <th v-if="auth.isPlatform" class="text-left px-4 py-3 font-medium">Client</th>
            <th class="text-left px-4 py-3 font-medium">Created</th>
            <th class="text-left px-4 py-3 font-medium">Status</th>
            <th class="px-4 py-3"></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="u in users" :key="u.id" class="border-t border-gray-200">
            <td class="px-4 py-3 font-medium">{{ u.full_name }}</td>
            <td class="px-4 py-3 text-gray-600">{{ u.email }}</td>
            <td class="px-4 py-3">
              <select :value="u.role" @change="changeRole(u, ($event.target as HTMLSelectElement).value)" :disabled="u.id === auth.user?.id"
                class="px-2 py-1 border rounded text-xs">
                <option v-for="(label, value) in roles" :key="value" :value="value">{{ label }}</option>
              </select>
            </td>
            <td v-if="auth.isPlatform" class="px-4 py-3 text-gray-600">{{ clientName(u.client_id) }}</td>
            <td class="px-4 py-3 text-gray-600">{{ new Date(u.created_at).toLocaleDateString() }}</td>
            <td class="px-4 py-3">
              <span :class="u.is_active ? 'bg-green-100 text-green-800' : 'bg-gray-200 text-gray-700'" class="px-2 py-0.5 rounded text-xs">
                {{ u.is_active ? 'active' : 'disabled' }}
              </span>
            </td>
            <td class="px-4 py-3 text-right">
              <button v-if="u.id !== auth.user?.id" @click="toggle(u)" class="text-xs text-[#2d7ab3] hover:underline">
                {{ u.is_active ? 'Disable' : 'Enable' }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { createUser, getUsers, updateUser, type AppUser } from '@/api/users'
import { getClients, type Client } from '@/api/clients'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const users = ref<AppUser[]>([])
const clients = ref<Client[]>([])
const loading = ref(true)
const loadError = ref('')
const busy = ref(false)
const error = ref('')
const roles: Record<string, string> = { soc_l1: 'L1 analyst', soc_l2: 'L2 analyst', soc_l3: 'L3 analyst', admin: 'Administrator' }
const form = reactive({ full_name: '', email: '', role: 'soc_l1', password: '', client_id: '' })

const canCreate = computed(() => form.full_name.trim() && form.email.includes('@') && form.password.length >= 8)

function clientName(id: string | null) {
  if (!id) return 'All clients'
  return clients.value.find(c => c.id === id)?.name || '—'
}

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    users.value = await getUsers()
    if (auth.isPlatform) clients.value = await getClients()
  } catch (e: any) {
    loadError.value = e?.response?.data?.detail || 'The ORION backend did not answer.'
  } finally {
    loading.value = false
  }
}

async function add() {
  busy.value = true
  error.value = ''
  try {
    await createUser({
      full_name: form.full_name.trim(), email: form.email.trim(), role: form.role, password: form.password,
      client_id: form.client_id || undefined,
    })
    Object.assign(form, { full_name: '', email: '', role: 'soc_l1', password: '', client_id: '' })
    await load()
  } catch (e: any) {
    const detail = e?.response?.data?.detail
    error.value = typeof detail === 'string' ? detail : 'Could not create the user. Check the email and the password length.'
  } finally {
    busy.value = false
  }
}

async function changeRole(u: AppUser, role: string) {
  try {
    await updateUser(u.id, { role })
  } finally {
    await load()
  }
}

async function toggle(u: AppUser) {
  await updateUser(u.id, { is_active: !u.is_active })
  await load()
}

onMounted(load)
</script>
