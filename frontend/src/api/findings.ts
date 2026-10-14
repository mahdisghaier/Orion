import api from './client'

// [explain] A finding as the screen receives it, including the priority score and why, repeats, who else saw it and suppression.
export interface Finding {
  id: string
  hunt_id: string
  siem_type: 'elastic' | 'sentinel' | 'wazuh'
  event_time: string
  source_ip: string | null
  destination_ip: string | null
  user_name: string | null
  host_name: string | null
  process_name: string | null
  process_command_line: string | null
  action: string | null
  ecs_event: Record<string, any>
  mitre_techniques: string[] | null
  mitre_mapping_source: string
  analyst_status: 'new' | 'validated' | 'false_positive' | 'escalated'
  occurrence_count: number
  correlation_id: string | null
  corroborated_by: { id: string; siem_type: string }[]
  suppression_id: string | null
  priority_score: number | null
  priority_breakdown: { factor: string; points: number; detail: string }[] | null
  suppressed: boolean
  previous_hunts: number
  known_since: string | null
  first_seen: string | null
  last_seen: string | null
  analyst_comment: string | null
  reviewed_by: string | null
  reviewed_at: string | null
  incident_id: string | null
  created_at: string
}

export interface PaginatedFindings {
  items: Finding[]
  total: number
  page: number
  page_size: number
  has_next: boolean
}

export interface FindingFilters {
  page?: number
  page_size?: number
  siem_type?: string
  analyst_status?: string
  corroborated?: boolean
  include_suppressed?: boolean
  collapse_repeats?: boolean
  sort?: 'priority' | 'time'
  source_ip?: string
  host_name?: string
  hunt_id?: string
}

// [explain] The main list; the filters become query parameters (SIEM, status, corroborated, sort, show repeats / suppressed...).
export async function getFindings(filters: FindingFilters = {}): Promise<PaginatedFindings> {
  const params = new URLSearchParams()
  if (filters.page) params.append('page', String(filters.page))
  if (filters.page_size) params.append('page_size', String(filters.page_size))
  if (filters.siem_type) params.append('siem_type', filters.siem_type)
  if (filters.analyst_status) params.append('analyst_status', filters.analyst_status)
  if (filters.corroborated !== undefined) params.append('corroborated', String(filters.corroborated))
  if (filters.include_suppressed) params.append('include_suppressed', 'true')
  if (filters.collapse_repeats === false) params.append('collapse_repeats', 'false')
  if (filters.sort) params.append('sort', filters.sort)
  if (filters.source_ip) params.append('source_ip', filters.source_ip)
  if (filters.host_name) params.append('host_name', filters.host_name)
  if (filters.hunt_id) params.append('hunt_id', filters.hunt_id)

  const { data } = await api.get(`/findings/?${params.toString()}`)
  return data
}

// [explain] One finding in full.
export async function getFinding(id: string): Promise<Finding> {
  const { data } = await api.get(`/findings/${id}`)
  return data
}

// [explain] Validate, mark false positive, or comment (L2+).
export async function updateFinding(
  id: string,
  update: { analyst_status?: string; analyst_comment?: string }
): Promise<Finding> {
  const { data } = await api.patch(`/findings/${id}`, update)
  return data
}

// [explain] Turn a finding into an incident (L2+).
export async function escalateFinding(
  id: string,
  escalate: { incident_id?: string; new_incident_title?: string; new_incident_severity?: string }
): Promise<any> {
  const { data } = await api.post(`/findings/${id}/escalate`, escalate)
  return data
}

export interface ContextEvent {
  time: string | null
  host: string | null
  user: string | null
  process_name: string | null
  pid: number | null
  command_line: string | null
  action: string | null
  message: string | null
  rule_id: string | null
  severity: number | null
}

export interface FindingContext {
  pivot: 'host' | 'process' | 'user'
  entity: Record<string, string | null>
  siem_type: string
  connection_name: string
  window_minutes: number
  time_from: string
  time_to: string
  count: number
  events: ContextEvent[]
}

// [explain] The "Related events" panel: events around the finding in its own SIEM.
export async function getFindingContext(
  id: string,
  pivot: 'host' | 'process' | 'user',
  window: number,
): Promise<FindingContext> {
  const { data } = await api.get(`/findings/${id}/context`, { params: { pivot, window } })
  return data
}

// [explain] "Known benign, hide it from now on" (L2+, reversible).
export async function suppressFinding(id: string, comment: string): Promise<{ suppression_id: string; affected: number }> {
  const { data } = await api.post(`/findings/${id}/suppress`, { comment: comment || null })
  return data
}

// [explain] Take the suppression back.
export async function unsuppressFinding(id: string): Promise<{ suppression_id: string; affected: number }> {
  const { data } = await api.delete(`/findings/${id}/suppress`)
  return data
}
