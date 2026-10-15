import api from './client'

export interface RunBrief {
  id: string
  status: 'running' | 'findings' | 'clear' | 'incomplete' | 'error'
  trigger: 'schedule' | 'manual'
  started_at: string
  finished_at: string | null
  headline: string | null
  error: string | null
}

export interface Job {
  id: string
  name: string
  kind: string
  interval_hours: number
  enabled: boolean
  config: Record<string, any>
  created_at: string
  last_run_at: string | null
  next_run_at: string | null
  running: boolean
  latest_run: RunBrief | null
}

export interface RunDetail {
  id: string
  job_id: string
  started_at: string
  finished_at: string | null
  status: RunBrief['status']
  trigger: string
  error: string | null
  summary: Record<string, any> | null
}

export interface Notification {
  id: string
  kind: string
  title: string
  body: string
  severity: 'info' | 'warning' | 'critical'
  run_id: string | null
  created_at: string
  acknowledged_at: string | null
}

export interface CoverageCell {
  connection: string
  siem_type: string
  status: 'runnable' | 'blind' | 'not_runnable' | 'archive' | 'unknown'
  reasons: string[]
}

export interface Coverage {
  connections: { name: string; type: string }[]
  rows: { technique: string; tactic: string; title: string; cells: CoverageCell[] }[]
  summary: { cells: Record<string, number>; rules: number; rules_runnable_somewhere: number }
}

export async function listJobs(): Promise<Job[]> {
  const { data } = await api.get('/jobs/')
  return data
}

export async function createJob(body: { name?: string; interval_hours?: number }): Promise<Job> {
  const { data } = await api.post('/jobs/', body)
  return data
}

export async function updateJob(id: string, body: { enabled?: boolean; interval_hours?: number; name?: string }): Promise<Job> {
  const { data } = await api.patch(`/jobs/${id}`, body)
  return data
}

export async function runJobNow(id: string): Promise<void> {
  await api.post(`/jobs/${id}/run`)
}

export async function listRuns(jobId: string): Promise<RunBrief[]> {
  const { data } = await api.get(`/jobs/${jobId}/runs`)
  return data
}

export async function getRun(runId: string): Promise<RunDetail> {
  const { data } = await api.get(`/jobs/runs/${runId}`)
  return data
}

export async function listNotifications(unreadOnly = false): Promise<Notification[]> {
  const { data } = await api.get('/notifications/', { params: { unread: unreadOnly } })
  return data
}

export async function notificationSummary(): Promise<{ unread: number; worst: string | null }> {
  const { data } = await api.get('/notifications/summary')
  return data
}

export async function acknowledgeNotification(id: string): Promise<void> {
  await api.post(`/notifications/${id}/acknowledge`)
}

export async function acknowledgeAll(): Promise<void> {
  await api.post('/notifications/acknowledge-all')
}

export async function getCoverage(): Promise<Coverage> {
  const { data } = await api.get('/coverage/')
  return data
}

/** Download a file from an authenticated endpoint through a temporary link. */
export async function downloadFile(path: string, fallbackName: string): Promise<void> {
  const response = await api.get(path, { responseType: 'blob' })
  const match = /filename="?([^";]+)"?/.exec(response.headers['content-disposition'] || '')
  const url = URL.createObjectURL(response.data)
  const link = document.createElement('a')
  link.href = url
  link.download = match ? match[1] : fallbackName
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}
