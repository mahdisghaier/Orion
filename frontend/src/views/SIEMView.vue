<template>
  <div class="p-8">
    <div class="mb-6">
      <h1 class="text-2xl font-bold text-[#142840]">SIEM Connections</h1>
      <p class="text-sm text-gray-500 mt-1">
        What each connected SIEM can actually see. A hunt that finds nothing in a blind spot means
        &ldquo;could not look&rdquo;, not &ldquo;clean&rdquo;.
      </p>
    </div>

    <div v-if="loading" class="text-gray-500 py-8 text-center">Loading connections...</div>
    <div v-else-if="loadError" class="py-8 text-center">
      <p class="text-red-600 font-medium">Could not load connections.</p>
      <p class="text-sm text-gray-500 mt-1">{{ loadError }}</p>
      <button @click="load" class="mt-4 px-4 py-2 border rounded text-sm hover:bg-gray-50">Retry</button>
    </div>
    <div v-else-if="connections.length === 0" class="text-gray-500 py-8 text-center">No SIEM connections yet.</div>

    <div v-else class="space-y-4">
      <div v-for="c in connections" :key="c.id" class="bg-white border rounded-lg">
        <div class="p-4 flex flex-wrap items-center gap-3 justify-between">
          <div class="flex items-center gap-3">
            <span :class="typeBadge(c.type)" class="px-2 py-0.5 rounded text-xs font-medium">{{ c.type }}</span>
            <span class="font-medium">{{ c.name }}</span>
            <span v-if="!c.is_active" class="text-xs bg-gray-200 text-gray-600 px-2 py-0.5 rounded">inactive</span>
          </div>
          <div class="flex items-center gap-2">
            <span v-if="state[c.id]?.test" class="text-xs" :class="state[c.id]!.test!.success ? 'text-green-700' : 'text-red-600'">
              {{ state[c.id]!.test!.message }}<span v-if="state[c.id]!.test!.latency_ms !== null"> ({{ state[c.id]!.test!.latency_ms }} ms)</span>
            </span>
            <button @click="runTest(c.id)" :disabled="!c.is_active || state[c.id]?.busy" class="px-3 py-1.5 border rounded text-sm hover:bg-gray-50 disabled:opacity-40">
              Test
            </button>
            <button @click="runProfile(c.id)" :disabled="!c.is_active || state[c.id]?.busy" class="px-3 py-1.5 bg-[#1a4a7a] text-white rounded text-sm disabled:opacity-40">
              {{ state[c.id]?.profile ? 'Refresh profile' : 'Profile' }}
            </button>
          </div>
        </div>

        <div v-if="state[c.id]?.error" class="px-4 pb-4 text-sm text-red-600">{{ state[c.id]!.error }}</div>

        <div v-if="state[c.id]?.profile" class="border-t p-4">
          <template v-for="p in [state[c.id]!.profile!.profile]" :key="'p'">
            <p class="text-xs text-gray-500 mb-3">
              Measured {{ formatTime(state[c.id]!.profile!.collected_at) }} over the last {{ p.window_days }} days.
            </p>

            <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
              <div class="border rounded p-3">
                <p class="text-xs uppercase text-gray-500">Events, last {{ p.window_days }}d</p>
                <p class="text-xl font-bold">{{ p.recent_docs.toLocaleString() }}</p>
              </div>
              <div class="border rounded p-3">
                <p class="text-xs uppercase text-gray-500">Events, all time</p>
                <p class="text-xl font-bold">{{ p.total_docs.toLocaleString() }}</p>
              </div>
              <div class="border rounded p-3">
                <p class="text-xs uppercase text-gray-500">First event</p>
                <p class="text-sm font-medium">{{ p.earliest ? formatTime(p.earliest) : '—' }}</p>
              </div>
              <div class="border rounded p-3" :class="freshness(p.latest).stale ? 'border-amber-400 bg-amber-50' : ''">
                <p class="text-xs uppercase text-gray-500">Latest event</p>
                <p class="text-sm font-medium">{{ p.latest ? formatTime(p.latest) : '—' }}</p>
                <p class="text-xs mt-1" :class="freshness(p.latest).stale ? 'text-amber-700' : 'text-gray-500'">{{ freshness(p.latest).label }}</p>
              </div>
            </div>

            <p v-if="p.recent_docs === 0" class="text-sm text-amber-800 bg-amber-50 border border-amber-300 rounded p-3 mb-4">
              No events in the last {{ p.window_days }} days. This looks like an archive, or the data source stopped sending.
              Hunts still run on it, but they cannot tell you anything about current activity.
            </p>

            <div class="grid md:grid-cols-2 gap-6">
              <div>
                <h3 class="text-sm font-bold mb-2">Field population (recent events)</h3>
                <div v-for="(v, name) in p.fields" :key="name" class="flex items-center gap-2 py-0.5 text-xs">
                  <span class="font-mono w-52 truncate" :title="String(name)">{{ name }}</span>
                  <div class="flex-1 h-2 bg-gray-100 rounded overflow-hidden">
                    <div class="h-2" :class="v.pct === 0 ? 'bg-red-400' : v.pct < 20 ? 'bg-amber-400' : 'bg-green-500'" :style="{ width: Math.max(v.pct, v.pct > 0 ? 2 : 0) + '%' }"></div>
                  </div>
                  <span class="w-12 text-right" :class="v.pct === 0 ? 'text-red-600 font-bold' : ''">{{ v.pct }}%</span>
                </div>
                <p class="text-xs text-gray-500 mt-2">
                  A rule that needs a field at 0% is a blind spot on this SIEM and will not be run there.
                </p>
              </div>
              <div v-if="p.top.length">
                <h3 class="text-sm font-bold mb-2">Most common <span class="font-mono font-normal">{{ p.top_label }}</span></h3>
                <div v-for="t in p.top" :key="t.value" class="flex justify-between text-xs py-0.5 border-b border-gray-100">
                  <span class="truncate pr-2" :title="t.value">{{ t.value }}</span>
                  <span class="text-gray-600">{{ t.count.toLocaleString() }}</span>
                </div>
              </div>
            </div>
          </template>
        </div>
        <div v-else-if="!state[c.id]?.busy" class="border-t px-4 py-3 text-xs text-gray-500">
          Not profiled yet. Press Profile to measure what this SIEM can see.
        </div>
        <div v-if="state[c.id]?.busy" class="border-t px-4 py-3 text-xs text-gray-500">Working...</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref, onMounted } from 'vue'
import {
  getSIEMConnections, testSIEMConnection, collectSIEMProfile, getSIEMProfile,
  type SIEMConnection, type StoredProfile,
} from '@/api/siem'

interface RowState {
  busy: boolean
  error: string
  test: { success: boolean; message: string; latency_ms: number | null } | null
  profile: StoredProfile | null
}

const connections = ref<SIEMConnection[]>([])
const state = reactive<Record<string, RowState>>({})
const loading = ref(true)
const loadError = ref('')

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    connections.value = await getSIEMConnections()
    for (const c of connections.value) {
      state[c.id] = { busy: false, error: '', test: null, profile: null }
      state[c.id].profile = await getSIEMProfile(c.id).catch(() => null)
    }
  } catch (e: any) {
    loadError.value = e.response?.data?.detail || 'The ORION backend did not answer. Is it running on port 8000?'
  } finally {
    loading.value = false
  }
}

async function runTest(id: string) {
  const s = state[id]
  s.busy = true
  s.error = ''
  try {
    s.test = await testSIEMConnection(id)
  } catch (e: any) {
    s.error = e.response?.data?.detail || 'Test failed'
  } finally {
    s.busy = false
  }
}

async function runProfile(id: string) {
  const s = state[id]
  s.busy = true
  s.error = ''
  try {
    s.profile = await collectSIEMProfile(id)
  } catch (e: any) {
    s.error = e.response?.data?.detail || 'Profiling failed'
  } finally {
    s.busy = false
  }
}

function typeBadge(t: string): string {
  if (t === 'elastic') return 'bg-yellow-100 text-yellow-800'
  if (t === 'wazuh') return 'bg-green-100 text-green-800'
  return 'bg-blue-100 text-blue-800'
}

function formatTime(ts: string): string {
  return new Date(ts).toLocaleString()
}

// A source that stopped sending is a blind spot too: flag a latest event older than 1 hour
function freshness(latest: string | null): { label: string; stale: boolean } {
  if (!latest) return { label: 'no events', stale: true }
  const minutes = (Date.now() - new Date(latest).getTime()) / 60000
  if (minutes < 1) return { label: 'just now', stale: false }
  const label = minutes < 60 ? `${Math.round(minutes)} min ago`
    : minutes < 2880 ? `${Math.round(minutes / 60)} h ago`
    : `${Math.round(minutes / 1440)} days ago`
  return { label, stale: minutes > 60 }
}

onMounted(load)
</script>
