<template>
  <div class="p-8">
    <RouterLink to="/hunts" class="text-sm text-[#2d7ab3] hover:text-[#4da8da] mb-4 inline-block">← Back to Hunts</RouterLink>

    <div v-if="loading" class="text-center py-12 text-gray-500">Loading hunt...</div>

    <div v-else-if="hunt" class="space-y-6">
      <!-- Header -->
      <div class="flex justify-between items-start">
        <div>
          <h1 class="text-2xl font-bold text-[#142840]">Hunt Detail</h1>
          <p class="text-sm text-gray-500 mt-1">ID: {{ hunt.id }}</p>
        </div>
        <span :class="statusClass(hunt.status)" class="px-3 py-1 rounded text-sm font-medium">{{ hunt.status }}</span>
      </div>

      <!-- Stats grid -->
      <div class="grid grid-cols-4 gap-4">
        <div class="bg-white border rounded-lg p-4">
          <p class="text-xs uppercase text-gray-500 mb-1">Total Hits</p>
          <p class="text-2xl font-bold text-[#2d7ab3]">{{ hunt.total_hits }}</p>
        </div>
        <div class="bg-white border rounded-lg p-4">
          <p class="text-xs uppercase text-gray-500 mb-1">Hunt Type</p>
          <p class="font-medium">{{ hunt.hunt_type }}</p>
        </div>
        <div class="bg-white border rounded-lg p-4">
          <p class="text-xs uppercase text-gray-500 mb-1">Started</p>
          <p class="text-sm">{{ formatTime(hunt.started_at) }}</p>
        </div>
        <div class="bg-white border rounded-lg p-4">
          <p class="text-xs uppercase text-gray-500 mb-1">Completed</p>
          <p class="text-sm">{{ formatTime(hunt.completed_at) }}</p>
        </div>
      </div>

      <!-- Error (if any) -->
      <div v-if="hunt.error" class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm">
        <strong>Error:</strong> {{ hunt.error }}
      </div>

      <!-- Queries -->
      <div class="bg-white border rounded-lg p-6">
        <h2 class="text-lg font-bold mb-4">Generated Queries</h2>
        <div class="space-y-4">
          <div v-if="hunt.queries.elastic">
            <div class="flex items-center gap-2 mb-2">
              <span class="bg-yellow-100 text-yellow-800 px-2 py-0.5 rounded text-xs font-medium">elastic</span>
              <span class="text-xs text-gray-500">EQL</span>
            </div>
            <pre class="bg-gray-900 text-green-400 p-3 rounded text-xs font-mono overflow-x-auto">{{ hunt.queries.elastic }}</pre>
          </div>
          <div v-if="hunt.queries.wazuh">
            <div class="flex items-center gap-2 mb-2">
              <span class="bg-green-100 text-green-800 px-2 py-0.5 rounded text-xs font-medium">wazuh</span>
              <span class="text-xs text-gray-500">Lucene</span>
            </div>
            <pre class="bg-gray-900 text-green-400 p-3 rounded text-xs font-mono overflow-x-auto">{{ hunt.queries.wazuh }}</pre>
          </div>
          <div v-if="hunt.queries.sentinel">
            <div class="flex items-center gap-2 mb-2">
              <span class="bg-blue-100 text-blue-800 px-2 py-0.5 rounded text-xs font-medium">sentinel</span>
              <span class="text-xs text-gray-500">KQL</span>
            </div>
            <pre class="bg-gray-900 text-green-400 p-3 rounded text-xs font-mono overflow-x-auto">{{ hunt.queries.sentinel }}</pre>
          </div>
        </div>
      </div>

      <!-- Results -->
      <div class="bg-white border rounded-lg p-6">
        <h2 class="text-lg font-bold mb-4">Findings ({{ results.length }})</h2>
        <div v-if="results.length === 0" class="text-sm text-gray-500">No findings returned by this hunt.</div>
        <div v-else class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead class="bg-gray-50">
              <tr>
                <th class="text-left px-3 py-2 font-medium">Time</th>
                <th class="text-left px-3 py-2 font-medium">Process</th>
                <th class="text-left px-3 py-2 font-medium">Host</th>
                <th class="text-left px-3 py-2 font-medium">User</th>
                <th class="text-left px-3 py-2 font-medium">MITRE</th>
                <th class="text-left px-3 py-2 font-medium">Status</th>
                <th class="text-left px-3 py-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="f in results" :key="f.id" class="border-t border-gray-200 hover:bg-gray-50">
                <td class="px-3 py-2 text-xs text-gray-600">{{ formatTime(f.event_time) }}</td>
                <td class="px-3 py-2">
                  <div class="font-mono text-xs">{{ f.process_name || '—' }}</div>
                  <div v-if="f.process_command_line" class="text-xs text-gray-500 mt-1 truncate max-w-xs">{{ f.process_command_line }}</div>
                </td>
                <td class="px-3 py-2 text-gray-600">{{ f.host_name || '—' }}</td>
                <td class="px-3 py-2 text-gray-600">{{ f.user_name || '—' }}</td>
                <td class="px-3 py-2">
                  <span v-if="f.mitre_techniques?.length" class="bg-[#2d7ab3]/10 text-[#2d7ab3] px-2 py-0.5 rounded text-xs font-mono">{{ f.mitre_techniques[0] }}</span>
                </td>
                <td class="px-3 py-2">
                  <span :class="statusClass(f.analyst_status)" class="px-2 py-0.5 rounded text-xs">{{ f.analyst_status }}</span>
                </td>
                <td class="px-3 py-2">
                  <RouterLink :to="`/findings/${f.id}`" class="text-[#2d7ab3] hover:text-[#4da8da] text-xs font-medium">View →</RouterLink>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { getHunt, getHuntResults, type Hunt } from '@/api/hunts'
import type { Finding } from '@/api/findings'

const route = useRoute()
const hunt = ref<Hunt | null>(null)
const results = ref<Finding[]>([])
const loading = ref(true)

async function loadHunt() {
  loading.value = true
  try {
    const id = route.params.id as string
    hunt.value = await getHunt(id)
    results.value = await getHuntResults(id)
  } catch (e) {
    console.error('Failed to load hunt:', e)
  } finally {
    loading.value = false
  }
}

function formatTime(ts: string | null): string {
  if (!ts) return '—'
  return new Date(ts).toLocaleString()
}

function statusClass(status: string): string {
  const map: Record<string, string> = {
    new: 'bg-gray-100 text-gray-800',
    validated: 'bg-green-100 text-green-800',
    false_positive: 'bg-red-100 text-red-800',
    escalated: 'bg-purple-100 text-purple-800',
    pending: 'bg-gray-100 text-gray-800',
    running: 'bg-blue-100 text-blue-800',
    completed: 'bg-green-100 text-green-800',
    failed: 'bg-red-100 text-red-800',
  }
  return map[status] || 'bg-gray-100'
}

onMounted(() => { loadHunt() })
</script>
