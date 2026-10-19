<template>
  <div class="flex flex-col h-full">
    <div class="bg-white border-b px-6 py-4">
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-xl font-bold text-[#142840]">AI Hunt Assistant</h1>
          <p class="text-xs text-gray-500 mt-1">Describe the activity to hunt for in plain language</p>
        </div>
        <div class="flex items-center gap-2">
          <select v-if="needClient" v-model="clientId" class="px-2 py-1 border rounded text-xs">
            <option v-for="c in clients" :key="c.id" :value="c.id">{{ c.name }}</option>
          </select>
          <span class="text-xs text-gray-500 uppercase tracking-wider">SIEM:</span>
          <label v-for="conn in visibleConnections" :key="conn.id" class="flex items-center gap-1 px-2 py-1 border rounded text-xs cursor-pointer hover:bg-gray-50">
            <input type="checkbox" :value="conn.id" v-model="selectedSIEMs" class="w-3 h-3" />
            <span>{{ conn.name }}</span>
          </label>
          <button @click="chat.clear()" class="ml-2 text-xs text-gray-400 hover:text-red-500">Clear</button>
        </div>
      </div>
    </div>

    <div class="flex-1 overflow-y-auto p-6 space-y-4 bg-[#f5f8fc]">
      <div v-if="chat.messages.length === 0" class="text-center py-12">
        <div class="text-4xl mb-3">&#128269;</div>
        <p class="text-gray-500 text-sm">Describe the activity to hunt for.</p>
        <p class="text-gray-400 text-xs mt-2">Example: "netcat listeners on the Ubuntu server"</p>
      </div>

      <div v-for="(msg, i) in chat.messages" :key="i" class="flex" :class="msg.role === 'user' ? 'justify-end' : 'justify-start'">
        <div class="max-w-[80%] rounded-lg px-4 py-3" :class="msg.role === 'user' ? 'bg-[#2d7ab3] text-white' : 'bg-white border text-[#142840]'">
          <div class="text-xs font-semibold mb-1 uppercase tracking-wider opacity-60">{{ msg.role === 'user' ? 'You' : 'ORION AI' }}</div>
          <div class="text-sm whitespace-pre-wrap">{{ msg.content }}</div>
        </div>
      </div>

      <div v-if="chat.pendingSigmaRule" class="bg-white border-2 border-[#4da8da] rounded-lg p-4">
        <div class="flex items-center justify-between mb-2">
          <h3 class="font-bold text-sm text-[#142840]">Generated Sigma Rule</h3>
          <span class="text-xs bg-yellow-100 text-yellow-800 px-2 py-0.5 rounded">Awaiting Approval</span>
        </div>
        <pre class="bg-gray-900 text-green-400 p-3 rounded text-xs font-mono overflow-x-auto mb-3 max-h-64 overflow-y-auto">{{ chat.pendingSigmaRule }}</pre>
        <div class="flex gap-2">
          <button @click="chat.approve(selectedSIEMs)" :disabled="chat.loading" class="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded text-sm disabled:opacity-50">
            {{ chat.loading ? 'Running...' : 'Approve & Run Hunt' }}
          </button>
          <button @click="chat.reject()" :disabled="chat.loading" class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded text-sm disabled:opacity-50">
            Reject
          </button>
        </div>
      </div>

      <div v-if="chat.lastHuntId && chat.lastFindings.length && !chat.pendingSigmaRule" class="bg-white border rounded-lg p-4 flex flex-wrap gap-2 items-center">
        <span class="text-sm text-[#142840] mr-2">{{ chat.lastFindings.length }} finding(s) from this hunt.</span>
        <RouterLink :to="{ path: '/findings', query: { hunt_id: chat.lastHuntId } }" class="px-4 py-2 border rounded text-sm hover:bg-gray-50">Open the findings</RouterLink>
        <button @click="investigate" :disabled="investigating" class="px-4 py-2 bg-[#1a4a7a] text-white rounded text-sm disabled:opacity-50">
          {{ investigating ? 'Opening...' : 'Investigate and get a report' }}
        </button>
      </div>

      <div v-if="chat.loading" class="flex justify-start">
        <div class="bg-white border rounded-lg px-4 py-3 text-sm text-gray-500">
          <span class="inline-block animate-pulse">&#9679;</span> AI is thinking...
        </div>
      </div>
    </div>

    <div class="bg-white border-t p-4">
      <form @submit.prevent="send" class="flex gap-2">
        <input
          v-model="inputMessage"
          type="text"
          :disabled="chat.loading || chat.pendingSigmaRule !== null"
          placeholder="Describe what you want to hunt for..."
          class="flex-1 px-4 py-2 border rounded text-sm focus:outline-none focus:border-[#2d7ab3] disabled:opacity-50"
        />
        <button type="submit" :disabled="chat.loading || !inputMessage.trim() || chat.pendingSigmaRule !== null || selectedSIEMs.length === 0" class="px-6 py-2 bg-[#2d7ab3] hover:bg-[#4da8da] text-white rounded text-sm disabled:opacity-50">
          Send
        </button>
      </form>
      <p v-if="selectedSIEMs.length === 0" class="text-xs text-red-500 mt-2">Select at least one SIEM target above.</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { createInvestigation } from '@/api/investigations'
import { useChatStore } from '@/stores/chat'
import { getSIEMConnections, type SIEMConnection } from '@/api/siem'
import { getClients, type Client } from '@/api/clients'
import { useAuthStore } from '@/stores/auth'

const chat = useChatStore()
const inputMessage = ref('')
const siemConnections = ref<SIEMConnection[]>([])
const selectedSIEMs = ref<string[]>([])
const auth = useAuthStore()
const clients = ref<Client[]>([])
const clientId = ref('')
// staff of the SOC work for one client at a time: a hunt never mixes the SIEMs of several clients
const needClient = computed(() => auth.isPlatform && clients.value.length > 1)
const visibleConnections = computed(() => needClient.value ? siemConnections.value.filter(c => c.client_id === clientId.value) : siemConnections.value)
watch([clientId, siemConnections], () => { selectedSIEMs.value = visibleConnections.value.map(c => c.id) })

async function loadSIEMs() {
  try {
    siemConnections.value = (await getSIEMConnections()).filter(c => c.is_active)
    if (auth.isPlatform) {
      clients.value = await getClients()
      clientId.value = clients.value[0]?.id || ''
    }
    selectedSIEMs.value = visibleConnections.value.map(c => c.id)
  } catch (e) {
    console.error('Failed to load SIEM connections:', e)
  }
}

async function send() {
  if (!inputMessage.value.trim() || selectedSIEMs.value.length === 0) return
  const msg = inputMessage.value
  inputMessage.value = ''
  await chat.sendMessage(msg, selectedSIEMs.value)
}

const router = useRouter()
const investigating = ref(false)

// start an investigation from the top finding of the last hunt; its page exports the PDF report and the notebook
async function investigate() {
  const top = chat.lastFindings[0]
  if (!top) return
  investigating.value = true
  try {
    const inv = await createInvestigation({
      title: chat.lastIntent.slice(0, 120) || 'Investigation from the assistant',
      hypothesis: chat.lastIntent || 'Follow-up of a hunt run from the assistant',
      from_finding_id: top.id,
    })
    router.push(`/investigations/${inv.id}`)
  } catch (e: any) {
    chat.messages.push({ role: 'assistant', content: 'Could not open the investigation: ' + (e.response?.data?.detail || e.message) })
  } finally {
    investigating.value = false
  }
}

onMounted(() => { loadSIEMs() })
</script>
