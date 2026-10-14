import api from './client'

export interface InvestigationStep {
  id: string
  investigation_id: string
  seq: number
  kind: 'rule' | 'pivot'
  title: string
  rationale: string
  proposed_by: 'ai' | 'system' | 'analyst'
  payload: Record<string, any>
  assessment: {
    runnable?: boolean
    siem?: string
    targets?: { connection: string; siem_type: string; runnable: boolean; reasons: string[]; archive?: boolean }[]
  } | null
  status: 'proposed' | 'approved' | 'rejected' | 'executed' | 'failed'
  decided_by: string | null
  decided_at: string | null
  decision_comment: string | null
  hunt_id: string | null
  result: Record<string, any> | null
  error: string | null
  executed_at: string | null
  created_at: string
}

export interface Investigation {
  id: string
  title: string
  hypothesis: string
  status: 'open' | 'concluded'
  verdict: 'true_positive' | 'false_positive' | 'inconclusive' | null
  conclusion: string | null
  siem_targets: string[]
  source_finding_id: string | null
  created_by: string
  created_at: string
  concluded_at: string | null
  steps: InvestigationStep[]
}

export interface ProposeResult {
  new_steps: InvestigationStep[]
  rejected: { title: string; reason: string }[]
  notes: string[]
}

export async function listInvestigations(): Promise<Investigation[]> {
  const { data } = await api.get('/investigations/')
  return data
}

export async function getInvestigation(id: string): Promise<Investigation> {
  const { data } = await api.get(`/investigations/${id}`)
  return data
}

export async function createInvestigation(body: {
  title: string
  hypothesis: string
  from_finding_id?: string
}): Promise<Investigation> {
  const { data } = await api.post('/investigations/', body)
  return data
}

export async function proposeSteps(id: string): Promise<ProposeResult> {
  const { data } = await api.post(`/investigations/${id}/propose`)
  return data
}

export async function addRuleStep(
  id: string,
  body: { title: string; rationale?: string; sigma_rule: string },
): Promise<InvestigationStep> {
  const { data } = await api.post(`/investigations/${id}/steps`, body)
  return data
}

export async function approveStep(id: string, stepId: string, comment?: string): Promise<InvestigationStep> {
  const { data } = await api.post(`/investigations/${id}/steps/${stepId}/approve`, { comment: comment || null })
  return data
}

export async function rejectStep(id: string, stepId: string, comment?: string): Promise<InvestigationStep> {
  const { data } = await api.post(`/investigations/${id}/steps/${stepId}/reject`, { comment: comment || null })
  return data
}

export async function concludeInvestigation(
  id: string,
  body: { verdict: string; conclusion: string },
): Promise<Investigation> {
  const { data } = await api.post(`/investigations/${id}/conclude`, body)
  return data
}

/** Download the PDF report or the Jupyter notebook of an investigation through the authenticated API. */
export async function downloadExport(id: string, kind: 'report' | 'notebook'): Promise<void> {
  const path = kind === 'report' ? `/investigations/${id}/report.pdf` : `/investigations/${id}/notebook`
  const response = await api.get(path, { responseType: 'blob' })
  const disposition: string = response.headers['content-disposition'] || ''
  const match = /filename="?([^";]+)"?/.exec(disposition)
  const filename = match ? match[1] : kind === 'report' ? 'investigation-report.pdf' : 'investigation.ipynb'
  const url = URL.createObjectURL(response.data)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}
