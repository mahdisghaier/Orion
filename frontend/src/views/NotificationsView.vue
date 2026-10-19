<template>
  <div class="p-8">
    <div class="flex flex-wrap justify-between items-start gap-4 mb-6">
      <div>
        <h1 class="text-2xl font-bold text-[#142840]">Notifications</h1>
        <p class="text-sm text-gray-500 mt-1">Results of scheduled checks, including checks that found nothing.</p>
      </div>
      <button @click="markAll" :disabled="!items.some(n => !n.acknowledged_at)" class="px-4 py-2 border rounded text-sm hover:bg-gray-50 disabled:opacity-40">
        Acknowledge all
      </button>
    </div>

    <div v-if="loading" class="text-gray-500 py-8 text-center">Loading...</div>
    <div v-else-if="loadError" class="py-8 text-center">
      <p class="text-red-600 font-medium">Could not load notifications.</p>
      <p class="text-sm text-gray-500 mt-1">{{ loadError }}</p>
      <button @click="load" class="mt-4 px-4 py-2 border rounded text-sm hover:bg-gray-50">Retry</button>
    </div>
    <div v-else-if="items.length === 0" class="text-gray-500 py-8 text-center">Nothing yet. Notes appear after the first threat-intelligence check.</div>
    <div v-else class="space-y-3">
      <div v-for="n in items" :key="n.id" class="bg-white border rounded-lg p-4" :class="n.acknowledged_at ? 'opacity-60' : ''">
        <div class="flex flex-wrap justify-between gap-3">
          <div>
            <span :class="severity(n.severity)" class="px-2 py-0.5 rounded text-xs font-medium mr-2">{{ n.severity }}</span>
            <span class="font-medium">{{ n.title }}</span>
            <p class="text-sm text-gray-700 mt-2 whitespace-pre-line">{{ n.body }}</p>
            <p class="text-xs text-gray-500 mt-2">{{ new Date(n.created_at).toLocaleString() }}</p>
          </div>
          <div class="flex items-start gap-2">
            <RouterLink v-if="n.run_id" :to="{ path: '/threat-intel', query: { run: n.run_id } }" class="px-3 py-1.5 border rounded text-sm hover:bg-gray-50">Open the check</RouterLink>
            <button v-if="!n.acknowledged_at" @click="mark(n.id)" class="px-3 py-1.5 bg-[#1a4a7a] text-white rounded text-sm">Acknowledge</button>
            <span v-else class="text-xs text-gray-500 py-2">acknowledged</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { listNotifications, acknowledgeNotification, acknowledgeAll, type Notification } from '@/api/intel'

const items = ref<Notification[]>([])
const loading = ref(true)
const loadError = ref('')

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    items.value = await listNotifications()
  } catch (e: any) {
    loadError.value = e.response?.data?.detail || 'The ORION backend did not answer. Is it running on port 8000?'
  } finally {
    loading.value = false
  }
}

async function mark(id: string) {
  await acknowledgeNotification(id)
  await load()
}

async function markAll() {
  await acknowledgeAll()
  await load()
}

function severity(s: string): string {
  return s === 'critical' ? 'bg-red-100 text-red-800' : s === 'warning' ? 'bg-amber-100 text-amber-800' : 'bg-green-100 text-green-800'
}

onMounted(load)
</script>
