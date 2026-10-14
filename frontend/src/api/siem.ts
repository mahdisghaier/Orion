import api from './client'

export interface SIEMConnection {
  id: string
  name: string
  type: 'sentinel' | 'elastic' | 'wazuh'
  is_active: boolean
  created_at: string
}

export async function getSIEMConnections(): Promise<SIEMConnection[]> {
  const { data } = await api.get('/siem/')
  return data
}

export interface SIEMProfile {
  siem_type: string
  window_days: number
  total_docs: number
  recent_docs: number
  earliest: string | null
  latest: string | null
  fields: Record<string, { present: number; pct: number }>
  top_label: string | null
  top: { value: string; count: number }[]
}

export interface StoredProfile {
  siem_connection_id: string
  profile: SIEMProfile
  collected_at: string
}

export async function testSIEMConnection(id: string): Promise<{ success: boolean; message: string; latency_ms: number | null }> {
  const { data } = await api.post(`/siem/${id}/test`)
  return data
}

export async function collectSIEMProfile(id: string): Promise<StoredProfile> {
  const { data } = await api.post(`/siem/${id}/profile`)
  return data
}

export async function getSIEMProfile(id: string): Promise<StoredProfile | null> {
  try {
    const { data } = await api.get(`/siem/${id}/profile`)
    return data
  } catch (e: any) {
    if (e.response?.status === 404) return null
    throw e
  }
}
