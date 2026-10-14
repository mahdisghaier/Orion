<template>
  <div class="p-8">
    <!-- Header -->
    <div class="flex justify-between items-center mb-6">
      <div>
        <h1 class="text-2xl font-bold text-[#142840]">Findings</h1>
        <p class="text-sm text-gray-500 mt-1">{{ total }} total findings</p>
      </div>
      <div class="flex gap-2">
        <select v-model="filters.siem_type" @change="loadFindings" class="px-3 py-2 border rounded text-sm">
          <option value="">All SIEMs</option>
          <option value="elastic">Elastic</option>
          <option value="wazuh">Wazuh</option>
          <option value="sentinel">Sentinel</option>
        </select>
        <select v-model="filters.analyst_status" @change="loadFindings" class="px-3 py-2 border rounded text-sm">
          <option value="">All Status</option>
          <option value="new">New</option>
          <option value="validated">Validated</option>
          <option value="false_positive">False Positive</option>
          <option value="escalated">Escalated</option>
        </select>
      </div>
    </div>

    <!-- Loading state -->
    <div v-if="loading" class="text-center py-12 text-gray-500">Loading findings...</div>

    <!-- Empty state -->
    <div v-else-if="findings.length === 0" class="text-center py-12">
      <p class="text-gray-500">No findings yet.</p>
      <p class="text-sm text-gray-400 mt-2">Run a hunt to see findings here.</p>
    </div>

    <!-- Findings table -->
    <div v-else class="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-[#1a4a7a] text-white">
          <tr>
            <th class="text-left px-4 py-3 font-medium">Time</th>
            <th class="text-left px-4 py-3 font-medium">SIEM</th>
            <th class="text-left px-4 py-3 font-medium">Process</th>
            <th class="text-left px-4 py-3 font-medium">Host</th>
            <th class="text-left px-4 py-3 font-medium">User</th>
            <th class="text-left px-4 py-3 font-medium">MITRE</th>
            <th class="text-left px-4 py-3 font-medium">Status</th>
            <th class="text-left px-4 py-3 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="finding in findings"
            :key="finding.id"
            class="border-t border-gray-200 hover:bg-gray-50"
          >
            <td class="px-4 py-3 text-gray-600">{{ formatTime(finding.event_time) }}</td>
            <td class="px-4 py-3">
              <span :class="siemBadge(finding.siem_type)" class="px-2 py-0.5 rounded text-xs font-medium">
                {{ finding.siem_type }}
              </span>
            </td>
            <td class="px-4 py-3">
              <div class="font-mono text-xs">{{ finding.process_name || '—' }}</div>
              <div v-if="finding.process_command_line" class="text-xs text-gray-500 mt-1 truncate max-w-xs">{{ finding.process_command_line }}</div>
            </td>
            <td class="px-4 py-3 text-gray-600">{{ finding.host_name || '—' }}</td>
            <td class="px-4 py-3 text-gray-600">{{ finding.user_name || '—' }}</td>
            <td class="px-4 py-3">
              <div v-if="finding.mitre_techniques?.length" class="flex flex-wrap gap-1">
                <span v-for="t in finding.mitre_techniques" :key="t" class="bg-[#2d7ab3]/10 text-[#2d7ab3] px-2 py-0.5 rounded text-xs font-mono">
                  {{ t }}
                </span>
              </div>
              <span v-else class="text-gray-400">—</span>
            </td>
            <td class="px-4 py-3">
              <span :class="statusClass(finding.analyst_status)" class="px-2 py-0.5 rounded text-xs font-medium">
                {{ finding.analyst_status }}
              </span>
            </td>
            <td class="px-4 py-3">
              <RouterLink :to="`/findings/${finding.id}`" class="text-[#2d7ab3] hover:text-[#4da8da] text-xs font-medium">
                View →
              </RouterLink>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Pagination -->
    <div v-if="total > filters.page_size" class="flex justify-between items-center mt-4">
      <p class="text-sm text-gray-500">
        Showing {{ (filters.page - 1) * filters.page_size + 1 }} - {{ Math.min(filters.page * filters.page_size, total) }} of {{ total }}
      </p>
      <div class="flex gap-2">
        <button
          @click="prevPage"
          :disabled="filters.page === 1"
          class="px-3 py-1 border rounded text-sm disabled:opacity-50 hover:bg-gray-50"
        >
          ← Previous
        </button>
        <span class="px-3 py-1 text-sm">Page {{ filters.page }}</span>
        <button
          @click="nextPage"
          :disabled="!hasNext"
          class="px-3 py-1 border rounded text-sm disabled:opacity-50 hover:bg-gray-50"
        >
          Next →
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue'
import { getFindings, type Finding } from '@/api/findings'

const findings = ref<Finding[]>([])
const total = ref(0)
const loading = ref(true)
const hasNext = ref(false)

const filters = reactive({
  page: 1,
  page_size: 20,
  siem_type: '',
  analyst_status: '',
})

async function loadFindings() {
  loading.value = true
  try {
    const data = await getFindings({
      page: filters.page,
      page_size: filters.page_size,
      siem_type: filters.siem_type || undefined,
      analyst_status: filters.analyst_status || undefined,
    })
    findings.value = data.items
    total.value = data.total
    hasNext.value = data.has_next
  } catch (e) {
    console.error('Failed to load findings:', e)
  } finally {
    loading.value = false
  }
}

function nextPage() {
  if (hasNext.value) {
    filters.page++
    loadFindings()
  }
}

function prevPage() {
  if (filters.page > 1) {
    filters.page--
    loadFindings()
  }
}

function siemBadge(siem: string): string {
  if (siem === 'elastic') return 'bg-yellow-100 text-yellow-800'
  if (siem === 'wazuh') return 'bg-green-100 text-green-800'
  return 'bg-blue-100 text-blue-800'
}

function formatTime(ts: string): string {
  return new Date(ts).toLocaleString()
}

function statusClass(status: string): string {
  const map: Record<string, string> = {
    new: 'bg-gray-100 text-gray-800',
    validated: 'bg-green-100 text-green-800',
    false_positive: 'bg-red-100 text-red-800',
    escalated: 'bg-purple-100 text-purple-800',
  }
  return map[status] || 'bg-gray-100 text-gray-800'
}

onMounted(() => {
  loadFindings()
})
</script>
