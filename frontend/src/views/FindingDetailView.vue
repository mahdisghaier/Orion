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
          <p>{{ formatTime(finding.event_time) }}</p>
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
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { getFinding, updateFinding, escalateFinding, type Finding } from '@/api/findings'

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
