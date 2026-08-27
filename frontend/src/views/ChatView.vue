<template>
  <div class="flex flex-col h-full">
    <div class="bg-white border-b px-6 py-4">
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-xl font-bold text-[#142840]">AI Hunt Assistant</h1>
          <p class="text-xs text-gray-500 mt-1">Describe what you want to hunt for in plain English</p>
        </div>
        <div class="flex items-center gap-2">
          <span class="text-xs text-gray-500 uppercase tracking-wider">SIEM:</span>
          <label v-for="conn in siemConnections" :key="conn.id" class="flex items-center gap-1 px-2 py-1 border rounded text-xs cursor-pointer hover:bg-gray-50">
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
        <p class="text-gray-500 text-sm">Tell me what you want to hunt for.</p>
        <p class="text-gray-400 text-xs mt-2">Example: "Hunt for netcat backdoors on the Ubuntu VM"</p>
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
import { ref, onMounted } from 'vue'
import { useChatStore } from '@/stores/chat'
import { getSIEMConnections, type SIEMConnection } from '@/api/siem'

const chat = useChatStore()
const inputMessage = ref('')
const siemConnections = ref<SIEMConnection[]>([])
const selectedSIEMs = ref<string[]>([])

async function loadSIEMs() {
  try {
    siemConnections.value = await getSIEMConnections()
    selectedSIEMs.value = siemConnections.value.map(c => c.id)
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

onMounted(() => { loadSIEMs() })
</script>
