import api from './client'

export interface Client {
  id: string
  name: string
  is_active: boolean
  created_at: string
}

export async function getClients(): Promise<Client[]> {
  const { data } = await api.get('/clients/')
  return data
}

export async function createClient(name: string): Promise<Client> {
  const { data } = await api.post('/clients/', { name })
  return data
}

export async function setClientActive(id: string, is_active: boolean): Promise<Client> {
  const { data } = await api.patch(`/clients/${id}`, { is_active })
  return data
}
