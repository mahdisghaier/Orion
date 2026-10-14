import api from './client'
import type { Finding } from './findings'

export interface Hunt {
  id: string
  rule_id: string | null
  created_by: string
  siem_targets: string[]
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  queries: Record<string, string>
  time_range: Record<string, string> | null
  hunt_type: 'sigma' | 'kestrel'
  started_at: string | null
  completed_at: string | null
  total_hits: number
  error: string | null
  created_at: string
}

export interface PaginatedHunts {
  items: Hunt[]
  total: number
  page: number
  page_size: number
  has_next: boolean
}

export interface HuntCreate {
  rule_id?: string
  rule_yaml?: string
  siem_targets: string[]
  time_range?: Record<string, string>
  hunt_type?: 'sigma' | 'kestrel'
}

// [explain] The list of searches (paged).
export async function getHunts(filters: { page?: number; page_size?: number; status?: string } = {}): Promise<PaginatedHunts> {
  const params = new URLSearchParams()
  if (filters.page) params.append('page', String(filters.page))
  if (filters.page_size) params.append('page_size', String(filters.page_size))
  if (filters.status) params.append('status', filters.status)
  const { data } = await api.get(`/hunts/?${params.toString()}`)
  return data
}

// [explain] One search.
export async function getHunt(id: string): Promise<Hunt> {
  const { data } = await api.get(`/hunts/${id}`)
  return data
}

// [explain] The findings of one search.
export async function getHuntResults(id: string): Promise<Finding[]> {
  const { data } = await api.get(`/hunts/${id}/results`)
  return data
}

// [explain] Start a search.
export async function createHunt(payload: HuntCreate): Promise<Hunt> {
  const { data } = await api.post('/hunts/', payload)
  return data
}
