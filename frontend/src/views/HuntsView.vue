<template>
  <div class="p-8">
    <!-- Header -->
    <div class="flex justify-between items-center mb-6">
      <div>
        <h1 class="text-2xl font-bold text-[#142840]">Hunts</h1>
        <p class="text-sm text-gray-500 mt-1">{{ total }} total hunts</p>
      </div>
      <RouterLink
        to="/hunts/new"
        class="px-4 py-2 bg-[#2d7ab3] hover:bg-[#4da8da] text-white rounded text-sm font-medium"
      >
        + New Hunt
      </RouterLink>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="text-center py-12 text-gray-500">Loading hunts...</div>

    <!-- Empty state -->
    <div v-else-if="hunts.length === 0" class="text-center py-12">
      <p class="text-gray-500">No hunts yet.</p>
      <RouterLink to="/hunts/new" class="inline-block mt-4 px-4 py-2 bg-[#2d7ab3] text-white rounded text-sm">
        Run your first hunt
      </RouterLink>
    </div>

    <!-- [explain] The list of searches: when, how many findings, which SIEMs, and a link to the details. -->
    <!-- Hunts table -->
    <div v-else class="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-[#1a4a7a] text-white">
          <tr>
            <th class="text-left px-4 py-3 font-medium">Created</th>
            <th class="text-left px-4 py-3 font-medium">Type</th>
            <th class="text-left px-4 py-3 font-medium">Status</th>
            <th class="text-left px-4 py-3 font-medium">Hits</th>
            <th class="text-left px-4 py-3 font-medium">Query (Elastic)</th>
            <th class="text-left px-4 py-3 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="hunt in hunts" :key="hunt.id" class="border-t border-gray-200 hover:bg-gray-50">
            <td class="px-4 py-3 text-gray-600">{{ formatTime(hunt.created_at) }}</td>
            <td class="px-4 py-3">
              <span class="bg-gray-100 text-gray-800 px-2 py-0.5 rounded text-xs font-medium">{{ hunt.hunt_type }}</span>
            </td>
            <td class="px-4 py-3">
              <span :class="statusClass(hunt.status)" class="px-2 py-0.5 rounded text-xs font-medium">{{ hunt.status }}</span>
            </td>
            <td class="px-4 py-3 font-medium">{{ hunt.total_hits }}</td>
            <td class="px-4 py-3">
              <code v-if="hunt.queries.elastic" class="text-xs text-gray-700 block max-w-md truncate" :title="hunt.queries.elastic">{{ hunt.queries.elastic }}</code>
              <span v-else class="text-gray-400 text-xs">—</span>
            </td>
            <td class="px-4 py-3">
              <RouterLink :to="`/hunts/${hunt.id}`" class="text-[#2d7ab3] hover:text-[#4da8da] text-xs font-medium">View →</RouterLink>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Pagination -->
    <div v-if="total > pageSize" class="flex justify-between items-center mt-4">
      <p class="text-sm text-gray-500">
        Showing {{ (page - 1) * pageSize + 1 }} - {{ Math.min(page * pageSize, total) }} of {{ total }}
      </p>
      <div class="flex gap-2">
        <button @click="prevPage" :disabled="page === 1" class="px-3 py-1 border rounded text-sm disabled:opacity-50 hover:bg-gray-50">← Previous</button>
        <span class="px-3 py-1 text-sm">Page {{ page }}</span>
        <button @click="nextPage" :disabled="!hasNext" class="px-3 py-1 border rounded text-sm disabled:opacity-50 hover:bg-gray-50">Next →</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { getHunts, type Hunt } from '@/api/hunts'

const hunts = ref<Hunt[]>([])
const total = ref(0)
const loading = ref(true)
const hasNext = ref(false)
const page = ref(1)
const pageSize = 20

// [explain] Fetch the current page of searches from the server.
async function loadHunts() {
  loading.value = true
  try {
    const data = await getHunts({ page: page.value, page_size: pageSize })
    hunts.value = data.items
    total.value = data.total
    hasNext.value = data.has_next
  } catch (e) {
    console.error('Failed to load hunts:', e)
  } finally {
    loading.value = false
  }
}

// [explain] Pagination buttons: change the page number and reload.
function nextPage() {
  if (hasNext.value) { page.value++; loadHunts() }
}
function prevPage() {
  if (page.value > 1) { page.value--; loadHunts() }
}

function formatTime(ts: string): string {
  return new Date(ts).toLocaleString()
}

// [explain] The colour of the status badge (green = completed, red = failed...).
function statusClass(status: string): string {
  const map: Record<string, string> = {
    pending: 'bg-gray-100 text-gray-800',
    running: 'bg-blue-100 text-blue-800',
    completed: 'bg-green-100 text-green-800',
    failed: 'bg-red-100 text-red-800',
    cancelled: 'bg-yellow-100 text-yellow-800',
  }
  return map[status] || 'bg-gray-100'
}

onMounted(() => { loadHunts() })
</script>
