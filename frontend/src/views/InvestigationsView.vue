<template>
  <div class="p-8">
    <div class="flex justify-between items-start mb-6 gap-4">
      <div>
        <h1 class="text-2xl font-bold text-[#142840]">Investigations</h1>
        <p class="text-sm text-gray-500 mt-1">
          Hypotheses under test, with the steps proposed, validated and approved by analysts. Every step and decision is recorded.
        </p>
      </div>
      <button @click="showForm = !showForm" class="px-4 py-2 bg-[#1a4a7a] text-white rounded text-sm whitespace-nowrap">
        {{ showForm ? 'Cancel' : 'New investigation' }}
      </button>
    </div>

    <div v-if="showForm" class="bg-white border rounded-lg p-6 mb-6 space-y-4">
      <div>
        <label class="block text-xs uppercase text-gray-500 mb-1">Title</label>
        <input v-model="title" class="w-full px-3 py-2 border rounded text-sm" placeholder="e.g. Possible backdoor on a workstation" />
      </div>
      <div>
        <label class="block text-xs uppercase text-gray-500 mb-1">Hypothesis</label>
        <textarea v-model="hypothesis" rows="3" class="w-full px-3 py-2 border rounded text-sm"
          placeholder="Describe the suspected activity and what supports it."></textarea>
      </div>
      <div v-if="auth.isPlatform && clients.length > 1">
        <label class="block text-xs uppercase text-gray-500 mb-1">Client</label>
        <select v-model="clientId" class="w-full px-3 py-2 border rounded text-sm">
          <option value="" disabled>Select a client</option>
          <option v-for="c in clients" :key="c.id" :value="c.id">{{ c.name }}</option>
        </select>
      </div>
      <p class="text-xs text-gray-500">The investigation uses the active SIEM connections of the client.</p>
      <p v-if="formError" class="text-sm text-red-600">{{ formError }}</p>
      <button @click="create" :disabled="saving || !title.trim() || !hypothesis.trim() || (auth.isPlatform && clients.length > 1 && !clientId)" class="px-4 py-2 bg-[#1a4a7a] text-white rounded text-sm disabled:opacity-40">
        Create
      </button>
    </div>

    <div v-if="loading" class="text-center py-12 text-gray-500">Loading...</div>
    <div v-else-if="loadError" class="text-center py-12">
      <p class="text-red-600 font-medium">Could not load investigations.</p>
      <p class="text-sm text-gray-500 mt-1">{{ loadError }}</p>
      <button @click="load" class="mt-4 px-4 py-2 border rounded text-sm hover:bg-gray-50">Retry</button>
    </div>
    <div v-else-if="items.length === 0" class="text-center py-12 text-gray-500">
      No investigations yet. Create one, or press "Investigate" on a finding.
    </div>
    <div v-else class="space-y-3">
      <RouterLink v-for="i in items" :key="i.id" :to="`/investigations/${i.id}`"
        class="block bg-white border rounded-lg p-4 hover:border-[#2d7ab3]">
        <div class="flex justify-between items-start gap-4">
          <div>
            <p class="font-medium">{{ i.title }}</p>
            <p class="text-sm text-gray-600 mt-1 line-clamp-2">{{ i.hypothesis }}</p>
          </div>
          <div class="text-right whitespace-nowrap">
            <span :class="i.status === 'open' ? 'bg-blue-100 text-blue-800' : 'bg-gray-200 text-gray-700'" class="px-2 py-0.5 rounded text-xs font-medium">
              {{ i.status }}<template v-if="i.verdict"> &middot; {{ i.verdict.replace('_', ' ') }}</template>
            </span>
            <p class="text-xs text-gray-500 mt-2">
              {{ i.steps.filter(s => s.status === 'executed').length }} step(s) run,
              {{ i.steps.filter(s => s.status === 'proposed').length }} waiting
            </p>
          </div>
        </div>
      </RouterLink>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { listInvestigations, createInvestigation, type Investigation } from '@/api/investigations'
import { getClients, type Client } from '@/api/clients'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const auth = useAuthStore()
const clients = ref<Client[]>([])
const clientId = ref('')
const items = ref<Investigation[]>([])
const loading = ref(true)
const loadError = ref('')
const showForm = ref(false)
const title = ref('')
const hypothesis = ref('')
const saving = ref(false)
const formError = ref('')

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    items.value = await listInvestigations()
  } catch (e: any) {
    loadError.value = e.response?.data?.detail || 'The ORION backend did not answer. Is it running on port 8000?'
  } finally {
    loading.value = false
  }
}

async function create() {
  saving.value = true
  formError.value = ''
  try {
    const inv = await createInvestigation({ title: title.value.trim(), hypothesis: hypothesis.value.trim(), client_id: clientId.value || undefined })
    router.push(`/investigations/${inv.id}`)
  } catch (e: any) {
    formError.value = e.response?.data?.detail || 'Could not create the investigation'
  } finally {
    saving.value = false
  }
}

onMounted(() => {
  load()
  if (auth.isPlatform) getClients().then(c => (clients.value = c)).catch(() => {})
})
</script>
