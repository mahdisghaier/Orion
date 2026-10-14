<template>
  <div class="p-8">
    <!-- Back link -->
    <RouterLink to="/findings" class="text-sm text-[#2d7ab3] hover:text-[#4da8da] mb-4 inline-block">
      ← Back to Findings
    </RouterLink>

    <!-- Loading -->
    <div v-if="loading" class="text-center py-12 text-gray-500">Loading finding...</div>

    <!-- Error -->
    <div v-else-if="error" class="text-center py-12 text-red-500">{{ error }}</div>

    <!-- Finding detail -->
    <div v-else-if="finding" class="space-y-6">
      <!-- Header -->
      <div class="flex justify-between items-start">
        <div>
          <h1 class="text-2xl font-bold text-[#142840]">Finding Detail</h1>
          <p class="text-sm text-gray-500 mt-1">ID: {{ finding.id }}</p>
        </div>
        <span :class="statusClass(finding.analyst_status)" class="px-3 py-1 rounded text-sm font-medium">
          {{ finding.analyst_status }}
        </span>
      </div>

      <!-- Key fields grid -->
      <div class="grid grid-cols-2 gap-4">
        <div class="bg-white border rounded-lg p-4">
          <p class="text-xs uppercase text-gray-500 mb-1">Process Name</p>
          <p class="font-mono">{{ finding.process_name || '—' }}</p>
        </div>
        <div class="bg-white border rounded-lg p-4">
          <p class="text-xs uppercase text-gray-500 mb-1">Command Line</p>
          <p class="font-mono text-sm break-all">{{ finding.process_command_line || '—' }}</p>
        </div>
        <div class="bg-white border rounded-lg p-4">
          <p class="text-xs uppercase text-gray-500 mb-1">Host</p>
          <p>{{ finding.host_name || '—' }}</p>
        </div>
        <div class="bg-white border rounded-lg p-4">
          <p class="text-xs uppercase text-gray-500 mb-1">User</p>
          <p>{{ finding.user_name || '—' }}</p>
        </div>
        <div class="bg-white border rounded-lg p-4">
          <p class="text-xs uppercase text-gray-500 mb-1">SIEM Source</p>
          <p>{{ finding.siem_type }}</p>
        </div>
        <div class="bg-white border rounded-lg p-4">
          <p class="text-xs uppercase text-gray-500 mb-1">Event Time</p>
          <p>{{ formatTime(finding.last_seen || finding.event_time) }}</p>
          <p v-if="finding.occurrence_count > 1" class="text-xs text-gray-500 mt-1">
            seen {{ finding.occurrence_count }}&times; since {{ formatTime(finding.first_seen || finding.event_time) }}
          </p>
        </div>
        <div class="bg-white border rounded-lg p-4">
          <p class="text-xs uppercase text-gray-500 mb-1">MITRE Techniques</p>
          <div v-if="finding.mitre_techniques?.length" class="flex flex-wrap gap-1 mt-1">
            <span v-for="t in finding.mitre_techniques" :key="t" class="bg-[#2d7ab3]/10 text-[#2d7ab3] px-2 py-0.5 rounded text-xs font-mono">
              {{ t }}
            </span>
          </div>
          <span v-else>—</span>
        </div>
        <div class="bg-white border rounded-lg p-4">
          <p class="text-xs uppercase text-gray-500 mb-1">Mapping Source</p>
          <p class="text-sm">{{ finding.mitre_mapping_source }}</p>
        </div>
      </div>

      <!-- Analyst workflow (L2+ only) -->
      <div v-if="auth.isL2Plus" class="bg-white border rounded-lg p-6">
        <h2 class="text-lg font-bold mb-4">Analyst Review</h2>

        <!-- Comment -->
        <div class="mb-4">
          <label class="block text-xs uppercase text-gray-500 mb-2">Comment</label>
          <textarea
            v-model="comment"
            rows="3"
            class="w-full px-3 py-2 border rounded text-sm focus:outline-none focus:border-[#2d7ab3]"
            placeholder="Add your analysis notes..."
          ></textarea>
        </div>

        <!-- Action buttons -->
        <div class="flex gap-2 flex-wrap">
          <button
            @click="updateStatus('validated')"
            :disabled="saving"
            class="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded text-sm disabled:opacity-50"
          >
            Mark as Validated (True Positive)
          </button>
          <button
            @click="updateStatus('false_positive')"
            :disabled="saving"
            class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded text-sm disabled:opacity-50"
          >
            Mark as False Positive
          </button>
          <button
            @click="showEscalateModal = true"
            :disabled="saving"
            class="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded text-sm disabled:opacity-50"
          >
            Escalate to Incident
          </button>
          <button
            @click="investigate"
            :disabled="saving"
            class="px-4 py-2 bg-[#1a4a7a] hover:bg-[#2d7ab3] text-white rounded text-sm disabled:opacity-50"
            title="Open an investigation starting from this finding"
          >
            Investigate
          </button>
          <button
            v-if="!finding.suppressed && finding.analyst_status !== 'validated' && finding.analyst_status !== 'escalated'"
            @click="showSuppressModal = true"
            :disabled="saving"
            class="px-4 py-2 bg-white border border-gray-400 hover:bg-gray-50 text-gray-800 rounded text-sm disabled:opacity-50"
            title="Hide this behaviour in future hunts (reversible)"
          >
            Suppress this pattern
          </button>
        </div>

        <!-- Existing review info -->
        <div v-if="finding.reviewed_by" class="mt-4 pt-4 border-t text-sm text-gray-500">
          Reviewed by {{ finding.reviewed_by }} at {{ formatTime(finding.reviewed_at!) }}
          <div v-if="finding.analyst_comment" class="mt-2">
            <strong>Comment:</strong> {{ finding.analyst_comment }}
          </div>
        </div>
      </div>

      <!-- L1 view (read-only) -->
      <div v-else class="bg-white border rounded-lg p-6">
        <p class="text-sm text-gray-500">
          You are signed in as <strong>{{ auth.user?.role }}</strong>. Only L2+ analysts can update finding status.
        </p>
        <div v-if="finding.analyst_comment" class="mt-3 text-sm">
          <strong>Analyst comment:</strong> {{ finding.analyst_comment }}
        </div>
      </div>

      <!-- Priority: deterministic score with its reasons -->
      <div v-if="finding.priority_score !== null" class="bg-white border rounded-lg p-6">
        <div class="flex items-baseline gap-3 mb-1">
          <h2 class="text-lg font-bold">Priority</h2>
          <span class="text-3xl font-bold" :class="finding.priority_score >= 70 ? 'text-red-700' : finding.priority_score >= 40 ? 'text-amber-700' : 'text-gray-700'">
            {{ finding.priority_score }}
          </span>
          <span class="text-sm text-gray-500">/ 100</span>
        </div>
        <p class="text-xs text-gray-500 mb-4">
          Computed by ORION from the evidence below, not by the AI. It is recomputed when an analyst decides on this pattern.
        </p>
        <table class="w-full text-sm">
          <tbody>
            <tr v-for="b in finding.priority_breakdown || []" :key="b.factor" class="border-t">
              <td class="py-2 pr-3 font-mono text-right w-16" :class="b.points > 0 ? 'text-green-700' : b.points < 0 ? 'text-red-700' : 'text-gray-400'">
                {{ b.points > 0 ? '+' : '' }}{{ b.points }}
              </td>
              <td class="py-2 pr-3 w-36 text-gray-700">{{ b.factor }}</td>
              <td class="py-2 text-gray-600">{{ b.detail }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- History + suppression state -->
      <div v-if="finding.suppressed" class="bg-gray-100 border border-gray-300 rounded-lg p-4 flex justify-between items-center gap-4">
        <div>
          <p class="text-sm font-medium text-gray-800">Suppressed: an analyst declared this pattern known benign.</p>
          <p class="text-xs text-gray-600 mt-1">It is hidden from the default findings list. Nothing was deleted.</p>
        </div>
        <button
          v-if="auth.isL2Plus"
          @click="doUnsuppress"
          :disabled="saving"
          class="px-3 py-1.5 bg-white border border-gray-400 rounded text-sm disabled:opacity-50 whitespace-nowrap"
        >
          Revoke suppression
        </button>
      </div>
      <div v-if="finding.previous_hunts > 0" class="bg-amber-50 border border-amber-200 rounded-lg p-4 text-sm text-amber-900">
        Not new: this same behaviour was already found in {{ finding.previous_hunts }} earlier hunt{{ finding.previous_hunts > 1 ? 's' : '' }},
        first seen {{ formatTime(finding.known_since) }}.
      </div>
      <div v-if="suppressNote" class="bg-blue-50 border border-blue-200 rounded-lg p-3 text-sm text-blue-900">{{ suppressNote }}</div>

      <!-- Corroboration: other SIEMs that reported the same behaviour in this hunt -->
      <div v-if="finding.corroborated_by?.length" class="bg-emerald-50 border border-emerald-200 rounded-lg p-4">
        <p class="text-sm font-medium text-emerald-800">
          Corroborated: also reported by
          <RouterLink
            v-for="c in finding.corroborated_by" :key="c.id"
            :to="`/findings/${c.id}`"
            class="underline mx-1"
          >{{ c.siem_type }}</RouterLink>
          for the same host and process in this hunt.
        </p>
        <p class="text-xs text-emerald-700 mt-1">
          Two independent sources agreeing is stronger evidence than one. Each SIEM keeps its own finding and event.
        </p>
      </div>

      <!-- Related events: read-only pivot into the finding's own SIEM -->
      <div class="bg-white border rounded-lg p-6">
        <h2 class="text-lg font-bold mb-1">Related events</h2>
        <p class="text-xs text-gray-500 mb-4">
          Read-only look at what the {{ finding.siem_type }} SIEM recorded around this finding.
          Fixed pivots only; every lookup is audited.
        </p>
        <div class="flex flex-wrap items-center gap-2 mb-4">
          <button
            v-for="p in pivots" :key="p.key"
            :disabled="!p.available || ctxLoading"
            @click="loadContext(p.key)"
            :class="ctx?.pivot === p.key ? 'bg-[#1a4a7a] text-white' : 'bg-white text-[#1a4a7a] border border-[#1a4a7a]'"
            class="px-3 py-1.5 rounded text-sm disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {{ p.label }}
          </button>
          <select v-model.number="ctxWindow" class="px-2 py-1.5 border rounded text-sm">
            <option :value="5">&plusmn; 5 min</option>
            <option :value="15">&plusmn; 15 min</option>
            <option :value="60">&plusmn; 60 min</option>
          </select>
        </div>

        <div v-if="ctxLoading" class="text-sm text-gray-500">Loading related events...</div>
        <div v-else-if="ctxError" class="text-sm text-red-600">{{ ctxError }}</div>
        <div v-else-if="ctx">
          <p class="text-xs text-gray-500 mb-2">
            {{ ctx.count }} event(s) from {{ ctx.connection_name }}, {{ formatTime(ctx.time_from) }} &ndash; {{ formatTime(ctx.time_to) }}
          </p>
          <p v-if="ctx.count === 0" class="text-sm text-gray-600">
            Nothing recorded in this window. That does not prove nothing happened: the SIEM may not collect this activity.
          </p>
          <div v-else class="overflow-x-auto max-h-96 overflow-y-auto border rounded">
            <table class="w-full text-xs">
              <thead class="bg-gray-100 sticky top-0">
                <tr>
                  <th class="text-left px-3 py-2">Time</th>
                  <th class="text-left px-3 py-2">Process / action</th>
                  <th class="text-left px-3 py-2">User</th>
                  <th class="text-left px-3 py-2">Details</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(ev, i) in ctx.events" :key="i" class="border-t">
                  <td class="px-3 py-2 whitespace-nowrap text-gray-600">{{ formatTime(ev.time) }}</td>
                  <td class="px-3 py-2 font-mono">
                    {{ ev.process_name || ev.action || '—' }}<span v-if="ev.pid" class="text-gray-400"> ({{ ev.pid }})</span>
                  </td>
                  <td class="px-3 py-2">{{ ev.user || '—' }}</td>
                  <td class="px-3 py-2 text-gray-600 break-all">{{ ev.command_line || ev.message || '' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Raw ECS event (collapsible) -->
      <div class="bg-white border rounded-lg p-6">
        <button
          @click="showRawEvent = !showRawEvent"
          class="flex items-center justify-between w-full"
        >
          <h2 class="text-lg font-bold">Raw ECS Event</h2>
          <span class="text-sm text-gray-500">{{ showRawEvent ? '▲ Hide' : '▼ Show' }}</span>
        </button>
        <div v-if="showRawEvent" class="mt-4 bg-gray-900 text-green-400 p-4 rounded text-xs font-mono overflow-x-auto max-h-96 overflow-y-auto">
          <pre>{{ JSON.stringify(finding.ecs_event, null, 2) }}</pre>
        </div>
      </div>
    </div>

    <!-- Escalate modal -->
    <div v-if="showSuppressModal" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div class="bg-white rounded-lg p-6 max-w-md w-full mx-4">
        <h2 class="text-xl font-bold mb-2">Suppress this pattern</h2>
        <p class="text-sm text-gray-600 mb-4">
          Future hunts will flag this exact behaviour (same SIEM, host, process, command line, user and action)
          as known benign and hide it by default. Unreviewed findings with the same pattern are hidden now.
          Validated or escalated findings are never hidden. You can revoke this at any time.
        </p>
        <label class="block text-xs uppercase text-gray-500 mb-2">Why is it benign?</label>
        <textarea
          v-model="suppressComment"
          rows="3"
          class="w-full px-3 py-2 border rounded text-sm focus:outline-none focus:border-[#2d7ab3]"
          placeholder="e.g., Lab listener started by the team for the demo"
        ></textarea>
        <div class="flex justify-end gap-2 mt-6">
          <button @click="showSuppressModal = false" class="px-4 py-2 border rounded text-sm hover:bg-gray-50">Cancel</button>
          <button
            @click="doSuppress"
            :disabled="saving"
            class="px-4 py-2 bg-gray-800 hover:bg-gray-900 text-white rounded text-sm disabled:opacity-50"
          >
            Suppress pattern
          </button>
        </div>
      </div>
    </div>

    <div v-if="showEscalateModal" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div class="bg-white rounded-lg p-6 max-w-md w-full mx-4">
        <h2 class="text-xl font-bold mb-4">Escalate to Incident</h2>
        <div class="space-y-4">
          <div>
            <label class="block text-xs uppercase text-gray-500 mb-2">Incident Title</label>
            <input
              v-model="escalateTitle"
              class="w-full px-3 py-2 border rounded text-sm focus:outline-none focus:border-[#2d7ab3]"
              placeholder="e.g., Backdoor listener on ubuntu-target"
            />
          </div>
          <div>
            <label class="block text-xs uppercase text-gray-500 mb-2">Severity</label>
            <select v-model="escalateSeverity" class="w-full px-3 py-2 border rounded text-sm">
              <option value="low">Low</option>
              <option value="medium" selected>Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
        </div>
        <div class="flex justify-end gap-2 mt-6">
          <button @click="showEscalateModal = false" class="px-4 py-2 border rounded text-sm hover:bg-gray-50">
            Cancel
          </button>
          <button
            @click="escalate"
            :disabled="saving || !escalateTitle"
            class="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded text-sm disabled:opacity-50"
          >
            Escalate
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { createInvestigation } from '@/api/investigations'
import {
  getFinding, updateFinding, escalateFinding, getFindingContext, suppressFinding, unsuppressFinding,
  type Finding, type FindingContext,
} from '@/api/findings'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const finding = ref<Finding | null>(null)
const loading = ref(true)
const saving = ref(false)
const error = ref('')
const comment = ref('')
const showRawEvent = ref(false)
const showEscalateModal = ref(false)
const escalateTitle = ref('')
const escalateSeverity = ref('medium')

const showSuppressModal = ref(false)

async function investigate() {
  if (!finding.value) return
  saving.value = true
  try {
    const f = finding.value
    const inv = await createInvestigation({
      title: `Investigate: ${f.process_name || f.action || 'finding'} on ${f.host_name || 'unknown host'}`,
      hypothesis: `Is the ${f.process_name || 'activity'} seen on ${f.host_name || 'this host'} ` +
        `(${f.siem_type}, priority ${f.priority_score ?? 'n/a'}) malicious, and how far did it go?`,
      from_finding_id: f.id,
    })
    router.push(`/investigations/${inv.id}`)
  } catch (e: any) {
    error.value = e.response?.data?.detail || 'Could not start an investigation'
  } finally {
    saving.value = false
  }
}
const suppressComment = ref('')
const suppressNote = ref('')

async function doSuppress() {
  if (!finding.value) return
  saving.value = true
  try {
    const r = await suppressFinding(finding.value.id, suppressComment.value)
    suppressNote.value = `Pattern suppressed. ${r.affected} unreviewed finding(s) flagged as known benign.`
    showSuppressModal.value = false
    suppressComment.value = ''
    await loadFinding()
  } catch (e: any) {
    error.value = e.response?.data?.detail || 'Failed to suppress pattern'
    showSuppressModal.value = false
  } finally {
    saving.value = false
  }
}

async function doUnsuppress() {
  if (!finding.value) return
  saving.value = true
  try {
    const r = await unsuppressFinding(finding.value.id)
    suppressNote.value = `Suppression revoked. ${r.affected} finding(s) are visible again.`
    await loadFinding()
  } catch (e: any) {
    error.value = e.response?.data?.detail || 'Failed to revoke suppression'
  } finally {
    saving.value = false
  }
}

const ctx = ref<FindingContext | null>(null)
const ctxLoading = ref(false)
const ctxError = ref('')
const ctxWindow = ref(15)

const pivots = computed(() => [
  { key: 'host' as const, label: 'Same host', available: !!finding.value?.host_name },
  { key: 'process' as const, label: 'Same process', available: !!finding.value?.process_name },
  { key: 'user' as const, label: 'Same user', available: !!finding.value?.user_name },
])

async function loadContext(pivot: 'host' | 'process' | 'user') {
  if (!finding.value) return
  ctxLoading.value = true
  ctxError.value = ''
  try {
    ctx.value = await getFindingContext(finding.value.id, pivot, ctxWindow.value)
  } catch (e: any) {
    ctx.value = null
    ctxError.value = e.response?.data?.detail || 'Failed to load related events'
  } finally {
    ctxLoading.value = false
  }
}

async function loadFinding() {
  loading.value = true
  try {
    const id = route.params.id as string
    finding.value = await getFinding(id)
    comment.value = finding.value.analyst_comment || ''
  } catch (e: any) {
    error.value = e.response?.data?.detail || 'Failed to load finding'
  } finally {
    loading.value = false
  }
}

async function updateStatus(status: 'validated' | 'false_positive') {
  if (!finding.value) return
  saving.value = true
  try {
    finding.value = await updateFinding(finding.value.id, {
      analyst_status: status,
      analyst_comment: comment.value,
    })
  } catch (e: any) {
    error.value = e.response?.data?.detail || 'Failed to update finding'
  } finally {
    saving.value = false
  }
}

async function escalate() {
  if (!finding.value || !escalateTitle.value) return
  saving.value = true
  try {
    await escalateFinding(finding.value.id, {
      new_incident_title: escalateTitle.value,
      new_incident_severity: escalateSeverity.value,
    })
    showEscalateModal.value = false
    await loadFinding()
  } catch (e: any) {
    error.value = e.response?.data?.detail || 'Failed to escalate finding'
  } finally {
    saving.value = false
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
  }
  return map[status] || 'bg-gray-100 text-gray-800'
}

onMounted(() => {
  loadFinding()
})
</script>
