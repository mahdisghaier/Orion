<template>
  <div class="p-8 max-w-4xl">
    <RouterLink to="/hunts" class="text-sm text-[#2d7ab3] hover:text-[#4da8da] mb-4 inline-block">← Back to Hunts</RouterLink>

    <h1 class="text-2xl font-bold text-[#142840] mb-6">New Hunt</h1>

    <div v-if="error" class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-6 text-sm">
      {{ error }}
    </div>

    <div class="space-y-6">
      <!-- [explain] Step 1: tick the SIEMs to ask. -->
      <!-- SIEM targets -->
      <div class="bg-white border rounded-lg p-6">
        <h2 class="text-lg font-bold mb-4">1. Select SIEM Targets</h2>
        <div v-if="loadingSIEM" class="text-sm text-gray-500">Loading connections...</div>
        <div v-else-if="siemConnections.length === 0" class="text-sm text-red-600">
          No active SIEM connections. Ask an admin to create one in the SIEM Connections page.
        </div>
        <div v-else class="space-y-2">
          <label v-for="conn in siemConnections" :key="conn.id" class="flex items-center gap-3 p-3 border rounded hover:bg-gray-50 cursor-pointer">
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

      <!-- [explain] Step 2: paste a Sigma rule. The server translates it for each SIEM. -->
      <!-- Sigma rule -->
      <div class="bg-white border rounded-lg p-6">
        <h2 class="text-lg font-bold mb-4">2. Sigma Rule (YAML)</h2>
        <p class="text-sm text-gray-500 mb-3">
          Paste a Sigma rule below. The backend will convert it to the native query of each selected SIEM (EQL for Elastic, Lucene for Wazuh) automatically.
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
          :disabled="saving || selectedSIEMs.length === 0 || !ruleYaml.trim()"
          class="px-6 py-2 bg-[#2d7ab3] hover:bg-[#4da8da] text-white rounded text-sm font-medium disabled:opacity-50"
        >
          {{ saving ? 'Running hunt...' : 'Run Hunt' }}
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { createHunt } from '@/api/hunts'
import { getSIEMConnections, type SIEMConnection } from '@/api/siem'

const router = useRouter()

const siemConnections = ref<SIEMConnection[]>([])
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

// [explain] Load the connected SIEMs so the analyst can tick which ones to ask.
async function loadSIEMs() {
  try {
    siemConnections.value = await getSIEMConnections()
  } catch (e) {
    console.error('Failed to load SIEM connections:', e)
  } finally {
    loadingSIEM.value = false
  }
}

// [explain] Fills the box with a ready-made Sigma rule to try.
function loadExample() {
  ruleYaml.value = exampleRule
}

// [explain] Send the rule and the chosen SIEMs; on success show the new search.
async function submitHunt() {
  error.value = ''
  saving.value = true
  try {
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
