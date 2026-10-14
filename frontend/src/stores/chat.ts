import { defineStore } from 'pinia'
import { ref } from 'vue'
import { sendMessage as apiSendMessage, confirmHunt, type ChatMessage, type ChatFinding } from '@/api/chat'

// [explain] Keeps the chat conversation in memory even when the analyst moves to another page and back.
export const useChatStore = defineStore('chat', () => {
  const messages = ref<ChatMessage[]>([])
  const pendingSigmaRule = ref<string | null>(null)
  const lastFindings = ref<ChatFinding[]>([])
  const loading = ref(false)

  // [explain] Add the analyst's message, ask the AI, and remember the rule it proposes (waiting for a yes).
  async function sendMessage(message: string, siemTargets: string[]) {
    messages.value.push({ role: 'user', content: message })
    loading.value = true
    try {
      const resp = await apiSendMessage(message, siemTargets, messages.value.slice(0, -1))
      messages.value = resp.chat_history
      if (resp.sigma_rule && resp.needs_confirmation) {
        pendingSigmaRule.value = resp.sigma_rule
      }
    } catch (e: any) {
      messages.value.push({ role: 'assistant', content: 'Error: ' + (e.response?.data?.detail || e.message) })
    } finally {
      loading.value = false
    }
  }

  // [explain] The analyst said yes: run the pending rule and show the findings in the chat.
  async function approve(siemTargets: string[]) {
    if (!pendingSigmaRule.value) return
    loading.value = true
    try {
      const resp = await confirmHunt(true, pendingSigmaRule.value, siemTargets, messages.value)
      messages.value = resp.chat_history
      pendingSigmaRule.value = null
      lastFindings.value = resp.findings
      if (resp.findings.length > 0) {
        let summary = '\n\nFindings:\n'
        for (const f of resp.findings) {
          summary += '- ' + (f.process_name || 'unknown') + ' | ' + (f.process_command_line || '') + ' | ' + (f.host_name || '') + ' | ' + (f.user_name || '') + '\n'
        }
        messages.value.push({ role: 'assistant', content: summary.trim() })
      }
      if (resp.follow_up_suggestions.length > 0) {
        let sugg = '\n\nSuggested follow-up queries:\n'
        for (const s of resp.follow_up_suggestions) {
          sugg += '- ' + s + '\n'
        }
        messages.value.push({ role: 'assistant', content: sugg.trim() })
      }
    } catch (e: any) {
      messages.value.push({ role: 'assistant', content: 'Hunt failed: ' + (e.response?.data?.detail || e.message) })
    } finally {
      loading.value = false
    }
  }

  // [explain] The analyst said no: forget the pending rule.
  function reject() {
    pendingSigmaRule.value = null
    messages.value.push({ role: 'assistant', content: 'Okay, I won\'t run that hunt. What would you like to hunt for instead?' })
  }

  // [explain] Start a fresh conversation.
  function clear() {
    messages.value = []
    pendingSigmaRule.value = null
    lastFindings.value = []
  }

  return { messages, pendingSigmaRule, lastFindings, loading, sendMessage, approve, reject, clear }
})
