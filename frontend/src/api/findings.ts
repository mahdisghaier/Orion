import api from './client'

export interface Finding {
  id: string
  hunt_id: string
  siem_type: 'elastic' | 'sentinel'
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
  source_ip?: string
  host_name?: string
  hunt_id?: string
}

export async function getFindings(filters: FindingFilters = {}): Promise<PaginatedFindings> {
  const params = new URLSearchParams()
  if (filters.page) params.append('page', String(filters.page))
  if (filters.page_size) params.append('page_size', String(filters.page_size))
  if (filters.siem_type) params.append('siem_type', filters.siem_type)
  if (filters.analyst_status) params.append('analyst_status', filters.analyst_status)
  if (filters.source_ip) params.append('source_ip', filters.source_ip)
  if (filters.host_name) params.append('host_name', filters.host_name)
  if (filters.hunt_id) params.append('hunt_id', filters.hunt_id)

  const { data } = await api.get(`/findings/?${params.toString()}`)
  return data
}

export async function getFinding(id: string): Promise<Finding> {
  const { data } = await api.get(`/findings/${id}`)
  return data
}

export async function updateFinding(
  id: string,
  update: { analyst_status?: string; analyst_comment?: string }
): Promise<Finding> {
  const { data } = await api.patch(`/findings/${id}`, update)
  return data
}

export async function escalateFinding(
  id: string,
  escalate: { incident_id?: string; new_incident_title?: string; new_incident_severity?: string }
): Promise<any> {
  const { data } = await api.post(`/findings/${id}/escalate`, escalate)
  return data
}
