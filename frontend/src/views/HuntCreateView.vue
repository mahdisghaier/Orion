<template>
  <div class="p-8 max-w-4xl">
    <RouterLink to="/hunts" class="text-sm text-[#2d7ab3] hover:text-[#4da8da] mb-4 inline-block">← Back to Hunts</RouterLink>

    <h1 class="text-2xl font-bold text-[#142840] mb-6">New Hunt</h1>

    <div v-if="error" class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-6 text-sm">
      {{ error }}
    </div>

    <div v-if="clientResults.length" class="bg-white border rounded-lg p-6 mb-6">
      <h2 class="text-lg font-bold mb-3">Results by client</h2>
      <table class="w-full text-sm">
        <thead class="text-left text-xs uppercase text-gray-500">
          <tr><th class="py-2">Client</th><th>Status</th><th>Findings</th><th></th></tr>
        </thead>
        <tbody>
          <tr v-for="r in clientResults" :key="r.client_id" class="border-t">
            <td class="py-2 font-medium">{{ r.client_name }}</td>
            <td>{{ r.status }}<span v-if="r.note" class="text-gray-500"> · {{ r.note }}</span></td>
            <td>{{ r.status === 'skipped' ? '—' : r.total_hits }}</td>
            <td class="text-right"><RouterLink v-if="r.hunt_id" :to="`/hunts/${r.hunt_id}`" class="text-[#2d7ab3] hover:underline">Open</RouterLink></td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="space-y-6">
      <!-- SIEM targets -->
      <div class="bg-white border rounded-lg p-6">
        <h2 class="text-lg font-bold mb-4">1. Select SIEM Targets</h2>
        <label v-if="needClient" class="flex items-start gap-2 mb-4 text-sm">
          <input type="checkbox" v-model="everyClient" class="mt-1" />
          <span>Run for every client. One separate hunt is run for each client, on its own SIEM connections; results are never mixed.</span>
        </label>
        <select v-if="needClient && !everyClient" v-model="clientId" class="mb-3 px-3 py-2 border rounded text-sm">
          <option v-for="c in clients" :key="c.id" :value="c.id">{{ c.name }}</option>
        </select>
        <div v-if="loadingSIEM" class="text-sm text-gray-500">Loading connections...</div>
        <div v-else-if="siemConnections.length === 0" class="text-sm text-red-600">
          No active SIEM connections. Ask an admin to create one in the SIEM Connections page.
        </div>
        <div v-else-if="!everyClient" class="space-y-2">
          <label v-for="conn in visibleConnections" :key="conn.id" class="flex items-center gap-3 p-3 border rounded hover:bg-gray-50 cursor-pointer">
            <input
              type="checkbox"
              :value="conn.id"
              v-model="selectedSIEMs"
              class="w-4 h-4"
            />
            <div>
              <p class="font-medium">{{ conn.name }}</p>
              <p class="text-xs text-gray-500">{{ conn.type }} · created {{ formatTime(conn.created_at) }}</p>
            </div>
          </label>
        </div>
      </div>

      <!-- Sigma rule -->
      <div class="bg-white border rounded-lg p-6">
        <h2 class="text-lg font-bold mb-4">2. Sigma Rule (YAML)</h2>
        <p class="text-sm text-gray-500 mb-3">
          Paste a Sigma rule. It is compiled to the native query of each selected SIEM (EQL for Elastic, Lucene for Wazuh).
        </p>
        <textarea
          v-model="ruleYaml"
          rows="20"
          class="w-full px-3 py-2 border rounded text-sm font-mono bg-gray-900 text-green-400 focus:outline-none focus:border-[#2d7ab3]"
          placeholder="title: ..."
        ></textarea>
        <div class="mt-2 flex gap-2">
          <button @click="loadExample" class="text-xs px-3 py-1 border rounded hover:bg-gray-50 text-[#2d7ab3]">
            Load Example (T1046)
          </button>
        </div>
      </div>

      <!-- Submit -->
      <div class="flex justify-end gap-2">
        <RouterLink to="/hunts" class="px-4 py-2 border rounded text-sm hover:bg-gray-50">Cancel</RouterLink>
        <button
          @click="submitHunt"
          :disabled="saving || (!everyClient && selectedSIEMs.length === 0) || !ruleYaml.trim()"
          class="px-6 py-2 bg-[#2d7ab3] hover:bg-[#4da8da] text-white rounded text-sm font-medium disabled:opacity-50"
        >
          {{ saving ? 'Running...' : everyClient ? 'Run for every client' : 'Run Hunt' }}
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { createHunt, createHuntForEveryClient, type ClientHuntResult } from '@/api/hunts'
import { getSIEMConnections, type SIEMConnection } from '@/api/siem'
import { getClients, type Client } from '@/api/clients'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()

const siemConnections = ref<SIEMConnection[]>([])
const auth = useAuthStore()
const clients = ref<Client[]>([])
const clientId = ref('')
const everyClient = ref(false)
const clientResults = ref<ClientHuntResult[]>([])
const needClient = computed(() => auth.isPlatform && clients.value.length > 1)
const visibleConnections = computed(() => needClient.value ? siemConnections.value.filter(c => c.client_id === clientId.value) : siemConnections.value)
const loadingSIEM = ref(true)
const selectedSIEMs = ref<string[]>([])
const ruleYaml = ref('')
const saving = ref(false)
const error = ref('')

const exampleRule = `title: Detection of Network Scanning Tools
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith:
      - /nc
      - /nc.openbsd
      - /ncat
      - /netcat
  condition: selection
tags:
  - attack.discovery
  - attack.t1046`

async function loadSIEMs() {
  try {
    siemConnections.value = (await getSIEMConnections()).filter(c => c.is_active)
    if (auth.isPlatform) {
      clients.value = await getClients()
      clientId.value = clients.value[0]?.id || ''
    }
  } catch (e) {
    console.error('Failed to load SIEM connections:', e)
  } finally {
    loadingSIEM.value = false
  }
}

function loadExample() {
  ruleYaml.value = exampleRule
}

async function submitHunt() {
  error.value = ''
  saving.value = true
  clientResults.value = []
  try {
    if (everyClient.value) {
      clientResults.value = await createHuntForEveryClient({ rule_yaml: ruleYaml.value })
      return
    }
    const hunt = await createHunt({
      rule_yaml: ruleYaml.value,
      siem_targets: selectedSIEMs.value,
    })
    router.push(`/hunts/${hunt.id}`)
  } catch (e: any) {
    error.value = e.response?.data?.detail || 'Failed to create hunt'
  } finally {
    saving.value = false
  }
}

function formatTime(ts: string): string {
  return new Date(ts).toLocaleString()
}

onMounted(() => { loadSIEMs() })
</script>
