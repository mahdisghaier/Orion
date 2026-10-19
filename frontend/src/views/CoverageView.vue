<template>
  <div class="p-8">
    <div class="flex flex-wrap justify-between items-start gap-4 mb-6">
      <div>
        <h1 class="text-2xl font-bold text-[#142840]">Hunt coverage</h1>
        <p class="text-sm text-gray-500 mt-1 max-w-3xl">
          Detection rules that can run on each connected SIEM. A blind cell means the SIEM does not record a field the rule needs.
        </p>
      </div>
      <button @click="exportLayer" :disabled="exporting" class="px-4 py-2 border rounded text-sm hover:bg-gray-50 disabled:opacity-50 whitespace-nowrap">
        Download ATT&amp;CK Navigator layer
      </button>
    </div>

    <div v-if="loading" class="text-gray-500 py-8 text-center">Loading...</div>
    <div v-else-if="loadError" class="py-8 text-center">
      <p class="text-red-600 font-medium">Could not load the coverage.</p>
      <p class="text-sm text-gray-500 mt-1">{{ loadError }}</p>
      <button @click="load" class="mt-4 px-4 py-2 border rounded text-sm hover:bg-gray-50">Retry</button>
    </div>
    <div v-else-if="data">
      <div class="flex flex-wrap gap-3 mb-4 text-sm">
        <span class="px-3 py-1 rounded bg-white border">
          <strong>{{ data.summary.rules_runnable_somewhere }}</strong> of {{ data.summary.rules }} rules can run on at least one SIEM
        </span>
        <span v-for="(n, s) in data.summary.cells" :key="s" class="px-3 py-1 rounded" :class="badge(String(s))">{{ n }} {{ label(String(s)) }}</span>
      </div>

      <div class="overflow-x-auto bg-white border rounded-lg">
        <table class="w-full text-sm">
          <thead class="bg-[#1a4a7a] text-white">
            <tr>
              <th class="text-left px-4 py-3 font-medium">Technique</th>
              <th class="text-left px-4 py-3 font-medium">Rule</th>
              <th v-for="c in data.connections" :key="c.name" class="text-left px-4 py-3 font-medium whitespace-nowrap">
                {{ c.name }}<span class="block text-xs opacity-70 font-normal">{{ c.type }}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in data.rows" :key="row.technique" class="border-t">
              <td class="px-4 py-3 font-mono text-xs whitespace-nowrap">{{ row.technique }}<span class="block text-gray-500 font-sans">{{ row.tactic?.replace('_', ' ') }}</span></td>
              <td class="px-4 py-3">{{ row.title }}</td>
              <td v-for="cell in row.cells" :key="cell.connection" class="px-4 py-3">
                <span :class="badge(cell.status)" class="px-2 py-0.5 rounded text-xs font-medium" :title="cell.reasons.join('; ')">{{ label(cell.status) }}</span>
                <p v-if="cell.reasons.length" class="text-xs text-gray-500 mt-1 max-w-[16rem]">{{ cell.reasons[0] }}</p>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="mt-4 text-xs text-gray-600 space-y-1">
        <p><strong>runnable</strong>: a field mapping exists and recent events carry every field the rule needs.</p>
        <p><strong>blind</strong>: the mapping exists but no recent event carries a needed field, so the rule would find nothing for the wrong reason.</p>
        <p><strong>not runnable</strong>: no mapping or no query for that SIEM. <strong>archive</strong>: no recent events. <strong>unknown</strong>: never profiled, or the profile is out of date (open SIEM Connections and press Profile).</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { getCoverage, downloadFile, type Coverage } from '@/api/intel'

const data = ref<Coverage | null>(null)
const loading = ref(true)
const loadError = ref('')
const exporting = ref(false)

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    data.value = await getCoverage()
  } catch (e: any) {
    loadError.value = e.response?.data?.detail || 'The ORION backend did not answer. Is it running on port 8000?'
  } finally {
    loading.value = false
  }
}

async function exportLayer() {
  exporting.value = true
  try {
    await downloadFile('/coverage/navigator', 'orion-coverage-layer.json')
  } finally {
    exporting.value = false
  }
}

function label(status: string): string {
  return status === 'not_runnable' ? 'not runnable' : status
}

function badge(status: string): string {
  return ({
    runnable: 'bg-green-100 text-green-800',
    blind: 'bg-red-100 text-red-800',
    not_runnable: 'bg-gray-200 text-gray-700',
    archive: 'bg-amber-100 text-amber-800',
    unknown: 'bg-blue-100 text-blue-800',
  } as Record<string, string>)[status] || 'bg-gray-100 text-gray-700'
}

onMounted(load)
</script>
