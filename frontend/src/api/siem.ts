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
