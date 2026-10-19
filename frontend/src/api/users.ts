import api from './client'

export interface AppUser {
  id: string
  email: string
  full_name: string
  role: 'admin' | 'soc_l1' | 'soc_l2' | 'soc_l3'
  client_id: string | null
  is_active: boolean
  created_at: string
}

export async function getUsers(): Promise<AppUser[]> {
  const { data } = await api.get('/users/')
  return data
}

export async function createUser(body: {
  email: string
  full_name: string
  role: string
  password: string
  client_id?: string
}): Promise<AppUser> {
  const { data } = await api.post('/users/', body)
  return data
}

export async function updateUser(id: string, body: { role?: string; is_active?: boolean; full_name?: string }): Promise<AppUser> {
  const { data } = await api.patch(`/users/${id}`, body)
  return data
}
