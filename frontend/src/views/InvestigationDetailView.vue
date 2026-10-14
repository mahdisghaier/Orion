<template>
  <div class="p-8">
    <RouterLink to="/investigations" class="text-sm text-[#2d7ab3] hover:text-[#4da8da] mb-4 inline-block">&larr; Back to Investigations</RouterLink>

    <div v-if="loading" class="text-center py-12 text-gray-500">Loading...</div>
    <div v-else-if="loadError" class="text-center py-12">
      <p class="text-red-600 font-medium">Could not load this investigation.</p>
      <p class="text-sm text-gray-500 mt-1">{{ loadError }}</p>
      <button @click="load" class="mt-4 px-4 py-2 border rounded text-sm hover:bg-gray-50">Retry</button>
    </div>

    <div v-else-if="inv" class="space-y-6">
      <!-- Header -->
      <div class="bg-white border rounded-lg p-6">
        <div class="flex justify-between items-start gap-4">
          <div>
            <h1 class="text-2xl font-bold text-[#142840]">{{ inv.title }}</h1>
            <p class="text-sm text-gray-700 mt-2"><span class="text-xs uppercase text-gray-500">Hypothesis</span><br />{{ inv.hypothesis }}</p>
            <p v-if="inv.source_finding_id" class="text-xs mt-2">
              Started from finding
              <RouterLink :to="`/findings/${inv.source_finding_id}`" class="text-[#2d7ab3] underline">{{ inv.source_finding_id.slice(0, 8) }}</RouterLink>
            </p>
          </div>
          <span :class="inv.status === 'open' ? 'bg-blue-100 text-blue-800' : 'bg-gray-200 text-gray-700'" class="px-3 py-1 rounded text-sm font-medium whitespace-nowrap">
            {{ inv.status }}<template v-if="inv.verdict"> &middot; {{ inv.verdict.replace('_', ' ') }}</template>
          </span>
        </div>
        <div v-if="inv.status === 'concluded'" class="mt-4 pt-4 border-t text-sm">
          <p class="text-xs uppercase text-gray-500">Conclusion</p>
          <p class="mt-1">{{ inv.conclusion }}</p>
          <p class="text-xs text-gray-500 mt-2">Closed {{ formatTime(inv.concluded_at) }}</p>
        </div>
      </div>

      <!-- Actions -->
      <div v-if="inv.status === 'open'" class="bg-white border rounded-lg p-6">
        <div class="flex flex-wrap items-center gap-3">
          <button @click="propose" :disabled="proposing" class="px-4 py-2 bg-[#1a4a7a] text-white rounded text-sm disabled:opacity-50">
            {{ proposing ? 'Thinking...' : 'Propose next steps' }}
          </button>
          <button @click="showAdd = !showAdd" class="px-4 py-2 border rounded text-sm hover:bg-gray-50">
            {{ showAdd ? 'Cancel' : 'Add my own rule' }}
          </button>
          <span v-if="proposing" class="text-xs text-gray-500">Asking the AI planner (gives up after about a minute)...</span>
          <span v-else class="text-xs text-gray-500">Nothing runs until you approve a step.</span>
        </div>

        <div v-if="showAdd" class="mt-4 space-y-3">
          <input v-model="addTitle" class="w-full px-3 py-2 border rounded text-sm" placeholder="Step title" />
          <textarea v-model="addRule" rows="9" class="w-full px-3 py-2 border rounded text-xs font-mono"
            placeholder="Sigma rule (YAML). It is checked against each SIEM's fields and data profile before it can be approved."></textarea>
          <p v-if="addError" class="text-sm text-red-600 whitespace-pre-line">{{ addError }}</p>
          <button @click="addStep" :disabled="!addTitle.trim() || !addRule.trim()" class="px-4 py-2 bg-[#1a4a7a] text-white rounded text-sm disabled:opacity-40">Add step</button>
        </div>

        <div v-for="n in notes" :key="n" class="mt-3 text-sm bg-amber-50 border border-amber-200 text-amber-900 rounded p-3">{{ n }}</div>
        <div v-if="rejected.length" class="mt-3 text-sm bg-gray-50 border rounded p-3">
          <p class="font-medium mb-1">Proposals refused by validation (never shown for approval):</p>
          <ul class="list-disc ml-5 text-gray-700">
            <li v-for="(r, i) in rejected" :key="i"><strong>{{ r.title }}</strong>: {{ r.reason }}</li>
          </ul>
        </div>
        <p v-if="actionError" class="mt-3 text-sm text-red-600">{{ actionError }}</p>
      </div>

      <!-- Timeline -->
      <div>
        <h2 class="text-lg font-bold mb-3">Steps</h2>
        <p v-if="inv.steps.length === 0" class="text-sm text-gray-500">No steps yet. Press "Propose next steps".</p>
        <div class="space-y-4">
          <div v-for="s in inv.steps" :key="s.id" class="bg-white border rounded-lg p-5" :class="s.status === 'rejected' ? 'opacity-70' : ''">
            <div class="flex flex-wrap items-center gap-2 mb-2">
              <span class="text-xs font-mono text-gray-500">#{{ s.seq }}</span>
              <span class="px-2 py-0.5 rounded text-xs font-medium" :class="s.kind === 'rule' ? 'bg-purple-100 text-purple-800' : 'bg-sky-100 text-sky-800'">{{ s.kind === 'rule' ? 'hunt a rule' : 'pivot' }}</span>
              <span class="px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">{{ proposer(s.proposed_by) }}</span>
              <span class="px-2 py-0.5 rounded text-xs font-medium" :class="statusClass(s.status)">{{ s.status }}</span>
            </div>
            <p class="font-medium">{{ s.title }}</p>
            <p class="text-sm text-gray-600 mt-1">{{ s.rationale }}</p>

            <!-- what it will do / where it can run -->
            <div v-if="s.kind === 'pivot'" class="text-xs text-gray-500 mt-2">
              Looks &plusmn;{{ s.payload.window_minutes }} min around the finding, same {{ s.payload.pivot }}, in the finding's own SIEM.
            </div>
            <div v-if="s.assessment?.targets" class="mt-2 text-xs space-y-0.5">
              <div v-for="t in s.assessment.targets" :key="t.connection">
                <span :class="t.runnable ? 'text-green-700' : 'text-red-600'">{{ t.runnable ? '&check;' : '&times;' }}</span>
                {{ t.connection }}
                <span v-if="!t.runnable" class="text-red-600">: {{ t.reasons.join('; ') }}</span>
                <span v-else-if="t.archive" class="text-amber-700">: archive, no recent events</span>
              </div>
            </div>
            <details v-if="s.kind === 'rule'" class="mt-2">
              <summary class="text-xs text-[#2d7ab3] cursor-pointer">Sigma rule</summary>
              <pre class="bg-gray-900 text-green-400 p-3 rounded text-xs font-mono overflow-x-auto mt-2">{{ s.payload.sigma_rule }}</pre>
            </details>

            <!-- decision -->
            <div v-if="s.status === 'proposed' && inv.status === 'open'" class="mt-4 pt-4 border-t">
              <input v-model="comments[s.id]" class="w-full px-3 py-2 border rounded text-sm mb-2" placeholder="Optional comment for the record" />
              <div class="flex gap-2">
                <button @click="decide(s, 'approve')" :disabled="busy[s.id]" class="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded text-sm disabled:opacity-50">
                  {{ busy[s.id] ? 'Running...' : 'Approve & run' }}
                </button>
                <button @click="decide(s, 'reject')" :disabled="busy[s.id]" class="px-4 py-2 border rounded text-sm hover:bg-gray-50 disabled:opacity-50">Reject</button>
              </div>
            </div>
            <p v-else-if="s.decided_at" class="text-xs text-gray-500 mt-3">
              {{ s.status === 'rejected' ? 'Rejected' : 'Approved' }} {{ formatTime(s.decided_at) }}<template v-if="s.decision_comment">: "{{ s.decision_comment }}"</template>
            </p>

            <!-- outcome -->
            <p v-if="s.error" class="mt-3 text-sm text-red-600 break-words">Failed: {{ s.error }}</p>
            <div v-if="s.status === 'executed' && s.result" class="mt-3 bg-gray-50 border rounded p-3 text-sm">
              <template v-if="s.kind === 'rule'">
                <p>
                  Hunt {{ s.result.hunt_status }}: <strong>{{ s.result.total_hits }}</strong> finding(s).
                  <RouterLink v-if="s.hunt_id" :to="`/hunts/${s.hunt_id}`" class="text-[#2d7ab3] underline ml-1">open hunt</RouterLink>
                </p>
                <p v-if="s.result.notes" class="text-xs text-amber-800 mt-1 break-words">{{ s.result.notes }}</p>
                <ul v-if="s.result.findings?.length" class="mt-2 text-xs space-y-0.5">
                  <li v-for="f in s.result.findings.slice(0, 5)" :key="f.id">
                    <RouterLink :to="`/findings/${f.id}`" class="text-[#2d7ab3] underline">{{ f.siem_type }} &middot; {{ f.process_name || '—' }} on {{ f.host_name || '—' }}</RouterLink>
                    <span class="text-gray-500"> &middot; priority {{ f.priority_score ?? '—' }}, seen {{ f.occurrences }}&times;</span>
                  </li>
                </ul>
              </template>
              <template v-else>
                <p><strong>{{ s.result.count }}</strong> related event(s) from {{ s.result.connection_name }}.</p>
                <details v-if="s.result.events?.length" class="mt-2">
                  <summary class="text-xs text-[#2d7ab3] cursor-pointer">Show events</summary>
                  <div class="overflow-x-auto max-h-64 overflow-y-auto mt-2 border rounded bg-white">
                    <table class="w-full text-xs">
                      <tbody>
                        <tr v-for="(e, i) in s.result.events" :key="i" class="border-t">
                          <td class="px-2 py-1 whitespace-nowrap text-gray-600">{{ formatTime(e.time) }}</td>
                          <td class="px-2 py-1 font-mono">{{ e.process_name || e.action || '—' }}</td>
                          <td class="px-2 py-1 text-gray-600 break-all">{{ e.command_line || e.message || '' }}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </details>
              </template>
            </div>
          </div>
        </div>
      </div>

      <!-- Conclude -->
      <div v-if="inv.status === 'open' && auth.isL2Plus" class="bg-white border rounded-lg p-6">
        <h2 class="text-lg font-bold mb-3">Conclude</h2>
        <div class="space-y-3">
          <select v-model="verdict" class="px-3 py-2 border rounded text-sm">
            <option value="">Verdict...</option>
            <option value="true_positive">True positive: real malicious activity</option>
            <option value="false_positive">False positive: benign</option>
            <option value="inconclusive">Inconclusive: cannot tell with the data available</option>
          </select>
          <textarea v-model="conclusion" rows="3" class="w-full px-3 py-2 border rounded text-sm" placeholder="What did you find, and what is it based on?"></textarea>
          <button @click="conclude" :disabled="!verdict || !conclusion.trim()" class="px-4 py-2 bg-gray-800 text-white rounded text-sm disabled:opacity-40">Close the investigation</button>
        </div>
      </div>
      <p v-else-if="inv.status === 'open'" class="text-xs text-gray-500">Only L2+ analysts can conclude an investigation.</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import {
  getInvestigation, proposeSteps, addRuleStep, approveStep, rejectStep, concludeInvestigation,
  type Investigation, type InvestigationStep,
} from '@/api/investigations'

const route = useRoute()
const auth = useAuthStore()
const id = route.params.id as string

const inv = ref<Investigation | null>(null)
const loading = ref(true)
const loadError = ref('')
const proposing = ref(false)
const actionError = ref('')
const notes = ref<string[]>([])
const rejected = ref<{ title: string; reason: string }[]>([])
const busy = reactive<Record<string, boolean>>({})
const comments = reactive<Record<string, string>>({})

const showAdd = ref(false)
const addTitle = ref('')
const addRule = ref('')
const addError = ref('')

const verdict = ref('')
const conclusion = ref('')

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    inv.value = await getInvestigation(id)
  } catch (e: any) {
    loadError.value = e.response?.data?.detail || 'The ORION backend did not answer. Is it running on port 8000?'
  } finally {
    loading.value = false
  }
}

async function propose() {
  proposing.value = true
  actionError.value = ''
  try {
    const r = await proposeSteps(id)
    notes.value = r.notes
    rejected.value = r.rejected
    inv.value = await getInvestigation(id)
  } catch (e: any) {
    actionError.value = e.response?.data?.detail || 'Could not propose steps'
  } finally {
    proposing.value = false
  }
}

async function addStep() {
  addError.value = ''
  try {
    await addRuleStep(id, { title: addTitle.value.trim(), sigma_rule: addRule.value })
    addTitle.value = ''
    addRule.value = ''
    showAdd.value = false
    inv.value = await getInvestigation(id)
  } catch (e: any) {
    addError.value = e.response?.data?.detail || 'The rule was refused'
  }
}

async function decide(step: InvestigationStep, action: 'approve' | 'reject') {
  busy[step.id] = true
  actionError.value = ''
  try {
    if (action === 'approve') await approveStep(id, step.id, comments[step.id])
    else await rejectStep(id, step.id, comments[step.id])
    inv.value = await getInvestigation(id)
  } catch (e: any) {
    actionError.value = e.response?.data?.detail || 'Action failed'
  } finally {
    busy[step.id] = false
  }
}

async function conclude() {
  actionError.value = ''
  try {
    inv.value = await concludeInvestigation(id, { verdict: verdict.value, conclusion: conclusion.value.trim() })
  } catch (e: any) {
    actionError.value = e.response?.data?.detail || 'Could not conclude'
  }
}

function proposer(p: string): string {
  return p === 'ai' ? 'proposed by AI' : p === 'system' ? 'rule-based suggestion' : 'added by you'
}

function statusClass(s: string): string {
  return ({
    proposed: 'bg-amber-100 text-amber-800',
    approved: 'bg-blue-100 text-blue-800',
    executed: 'bg-green-100 text-green-800',
    rejected: 'bg-gray-200 text-gray-700',
    failed: 'bg-red-100 text-red-800',
  } as Record<string, string>)[s] || 'bg-gray-100 text-gray-700'
}

function formatTime(ts: string | null): string {
  return ts ? new Date(ts).toLocaleString() : '—'
}

onMounted(load)
</script>
