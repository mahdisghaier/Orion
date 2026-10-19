<template>
  <div class="p-8">
    <h1 class="text-2xl font-bold text-[#142840]">Clients</h1>
    <p class="text-sm text-gray-500 mt-1">
      Each client has its own SIEM connections, hunts, findings, investigations and checks. A user bound to a client
      sees nothing of the others.
    </p>

    <form @submit.prevent="add" class="mt-6 flex gap-2 max-w-xl">
      <input v-model="name" placeholder="New client name" class="flex-1 px-3 py-2 border rounded text-sm" />
      <button :disabled="!name.trim() || busy" class="px-4 py-2 bg-[#1a4a7a] text-white rounded text-sm disabled:opacity-50">
        Add client
      </button>
    </form>
    <p v-if="error" class="text-sm text-red-600 mt-2">{{ error }}</p>

    <div class="mt-6 bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden max-w-3xl">
      <table class="w-full text-sm">
        <thead class="bg-[#1a4a7a] text-white">
          <tr>
            <th class="text-left px-4 py-3 font-medium">Client</th>
            <th class="text-left px-4 py-3 font-medium">Created</th>
            <th class="text-left px-4 py-3 font-medium">Status</th>
            <th class="px-4 py-3"></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="c in clients" :key="c.id" class="border-t border-gray-200">
            <td class="px-4 py-3 font-medium">{{ c.name }}</td>
            <td class="px-4 py-3 text-gray-600">{{ new Date(c.created_at).toLocaleDateString() }}</td>
            <td class="px-4 py-3">
              <span :class="c.is_active ? 'bg-green-100 text-green-800' : 'bg-gray-200 text-gray-700'" class="px-2 py-0.5 rounded text-xs">
                {{ c.is_active ? 'active' : 'inactive' }}
              </span>
            </td>
            <td class="px-4 py-3 text-right">
              <button @click="toggle(c)" class="text-xs text-[#2d7ab3] hover:underline">
                {{ c.is_active ? 'Deactivate' : 'Activate' }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { createClient, getClients, setClientActive, type Client } from '@/api/clients'

const clients = ref<Client[]>([])
const name = ref('')
const busy = ref(false)
const error = ref('')

async function load() {
  clients.value = await getClients()
}

async function add() {
  busy.value = true
  error.value = ''
  try {
    await createClient(name.value.trim())
    name.value = ''
    await load()
  } catch (e: any) {
    error.value = e?.response?.data?.detail || 'Could not create the client.'
  } finally {
    busy.value = false
  }
}

async function toggle(c: Client) {
  await setClientActive(c.id, !c.is_active)
  await load()
}

onMounted(load)
</script>
