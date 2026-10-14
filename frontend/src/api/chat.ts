import api from './client'

// [explain] The shapes of the data exchanged with /api/chat (what the screen sends and receives).
export interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
}

export interface ChatFinding {
  id: string
  process_name: string | null
  process_command_line: string | null
  host_name: string | null
  user_name: string | null
  event_time: string | null
  mitre_techniques: string[] | null
  siem_type: string
}

export interface ChatResponse {
  chat_history: ChatMessage[]
  sigma_rule: string | null
  needs_confirmation: boolean
  hunt_id: string | null
  hunt_status: string | null
  total_hits: number | null
  findings: ChatFinding[]
  explanation: string | null
  follow_up_suggestions: string[]
  error: string | null
}

// [explain] Send what the analyst typed. The AI answers with a proposed rule and waits for approval.
export async function sendMessage(
  message: string,
  siemTargets: string[],
  chatHistory: ChatMessage[]
): Promise<ChatResponse> {
  const { data } = await api.post('/chat/message', {
    message,
    siem_targets: siemTargets,
    chat_history: chatHistory,
  })
  return data
}

// [explain] Tell the AI "yes, run it" (or no).
export async function confirmHunt(
  approved: boolean,
  sigmaRule: string,
  siemTargets: string[],
  chatHistory: ChatMessage[]
): Promise<ChatResponse> {
  const { data } = await api.post('/chat/confirm', {
    approved,
    sigma_rule: sigmaRule,
    siem_targets: siemTargets,
    chat_history: chatHistory,
  })
  return data
}
