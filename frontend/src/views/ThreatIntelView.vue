<template>
  <div class="p-8">
    <div class="mb-6">
      <h1 class="text-2xl font-bold text-[#142840]">Threat intelligence</h1>
      <p class="text-sm text-gray-500 mt-1 max-w-3xl">
        On a schedule, ORION reads what attackers are doing now (exploited CVEs, recent campaigns, malicious addresses) and tests it
        against the data it can see. &ldquo;Nothing found&rdquo; always comes with the list of what it could <em>not</em> check.
      </p>
    </div>

    <div v-if="loading" class="text-gray-500 py-8 text-center">Loading...</div>
    <div v-else-if="loadError" class="py-8 text-center">
      <p class="text-red-600 font-medium">Could not load the checks.</p>
      <p class="text-sm text-gray-500 mt-1">{{ loadError }}</p>
      <button @click="load" class="mt-4 px-4 py-2 border rounded text-sm hover:bg-gray-50">Retry</button>
    </div>

    <div v-else>
      <div v-if="jobs.length === 0" class="bg-white border rounded-lg p-6 text-center">
        <p class="text-gray-600 mb-4">No scheduled check yet.</p>
        <button v-if="auth.isAdmin" @click="createDefault" :disabled="busy" class="px-4 py-2 bg-[#1a4a7a] text-white rounded text-sm disabled:opacity-50">
          Create the daily check
        </button>
        <p v-else class="text-sm text-gray-500">An administrator can create it.</p>
      </div>

      <div v-for="job in jobs" :key="job.id" class="bg-white border rounded-lg mb-6">
        <div class="p-5 flex flex-wrap items-center justify-between gap-4">
          <div>
            <p class="font-medium text-lg">{{ job.name }}</p>
            <p class="text-sm text-gray-600 mt-1">
              Every {{ job.interval_hours }} h &middot;
              <span :class="job.enabled ? 'text-green-700' : 'text-gray-500'">{{ job.enabled ? 'enabled' : 'disabled' }}</span> &middot;
              next run {{ job.enabled && job.next_run_at ? when(job.next_run_at) : 'not scheduled' }}
            </p>
          </div>
          <div class="flex flex-wrap items-center gap-2">
            <button v-if="auth.isL2Plus" @click="runNow(job)" :disabled="job.running || busy" class="px-4 py-2 bg-[#1a4a7a] text-white rounded text-sm disabled:opacity-50">
              {{ job.running ? 'Running...' : 'Run now' }}
            </button>
            <template v-if="auth.isAdmin">
              <button @click="toggle(job)" class="px-3 py-2 border rounded text-sm hover:bg-gray-50">{{ job.enabled ? 'Disable' : 'Enable' }}</button>
              <select :value="job.interval_hours" @change="setInterval(job, Number(($event.target as HTMLSelectElement).value))" class="px-2 py-2 border rounded text-sm">
                <option v-for="h in [6, 12, 24, 48, 72]" :key="h" :value="h">every {{ h }} h</option>
              </select>
            </template>
          </div>
        </div>

        <div class="border-t">
          <p v-if="(runs[job.id] || []).length === 0" class="p-5 text-sm text-gray-500">No run yet. {{ job.enabled ? 'The first one starts within a minute of creation.' : '' }}</p>
          <table v-else class="w-full text-sm">
            <tbody>
              <tr v-for="r in runs[job.id]" :key="r.id" class="border-t first:border-t-0 hover:bg-gray-50" :class="selected?.id === r.id ? 'bg-blue-50' : ''">
                <td class="px-5 py-3 whitespace-nowrap"><span :class="verdictBadge(r.status)" class="px-2 py-0.5 rounded text-xs font-medium">{{ verdictLabel(r.status) }}</span></td>
                <td class="px-3 py-3 text-gray-700">{{ r.headline || r.error || 'in progress...' }}</td>
                <td class="px-3 py-3 text-gray-500 whitespace-nowrap">{{ when(r.started_at) }} <span class="text-xs">({{ r.trigger }})</span></td>
                <td class="px-5 py-3 text-right whitespace-nowrap">
                  <button @click="openRun(r.id)" class="text-[#2d7ab3] underline mr-3">Details</button>
                  <button @click="report(r.id)" class="text-[#2d7ab3] underline">Report (PDF)</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <p v-if="actionError" class="text-sm text-red-600 mb-4">{{ actionError }}</p>

      <!-- Run detail -->
      <div v-if="selected" class="bg-white border rounded-lg p-6 space-y-6">
        <div class="flex flex-wrap justify-between items-start gap-3">
          <div>
            <span :class="verdictBadge(selected.status)" class="px-3 py-1 rounded text-sm font-medium">{{ verdictLabel(selected.status) }}</span>
            <p class="mt-3 font-medium">{{ selected.summary?.headline || selected.error }}</p>
            <p class="text-xs text-gray-500 mt-1">Window checked: {{ when(selected.summary?.window?.from) }} &ndash; {{ when(selected.summary?.window?.to) }}</p>
          </div>
          <button @click="selected = null" class="text-sm text-gray-500 hover:text-gray-800">Close</button>
        </div>

        <div v-if="selected.summary?.limits?.length" class="bg-amber-50 border border-amber-200 rounded p-4">
          <p class="font-medium text-amber-900 mb-2">What could NOT be checked</p>
          <ul class="list-disc ml-5 text-sm text-amber-900 space-y-1">
            <li v-for="(l, i) in selected.summary.limits" :key="i">{{ l }}</li>
          </ul>
        </div>

        <div v-if="selected.summary?.technique_hunts">
          <h3 class="font-bold mb-1">Techniques of recent campaigns</h3>
          <p class="text-xs text-gray-500 mb-2">
            {{ selected.summary.technique_hunts.campaign_techniques }} Linux techniques; ORION has a rule for {{ selected.summary.technique_hunts.with_rule }}.
          </p>
          <table v-if="selected.summary.technique_hunts.executed.length" class="w-full text-sm border">
            <thead class="bg-gray-100"><tr><th class="text-left px-3 py-2">Technique</th><th class="text-left px-3 py-2">Rule</th><th class="text-left px-3 py-2">Run on</th><th class="text-left px-3 py-2">Findings</th></tr></thead>
            <tbody>
              <tr v-for="h in selected.summary.technique_hunts.executed" :key="h.rule" class="border-t">
                <td class="px-3 py-2 font-mono text-xs">{{ h.technique }} <span class="font-sans text-gray-600">{{ h.name }}</span></td>
                <td class="px-3 py-2">{{ h.rule }}</td>
                <td class="px-3 py-2 text-xs">{{ h.siems.join(', ') }}</td>
                <td class="px-3 py-2">
                  <span :class="h.findings ? 'text-red-700 font-bold' : 'text-gray-600'">{{ h.findings }}</span>
                  <RouterLink v-for="t in h.top" :key="t.id" :to="`/findings/${t.id}`" class="ml-2 text-[#2d7ab3] underline text-xs">open</RouterLink>
                </td>
              </tr>
            </tbody>
          </table>
          <details v-if="selected.summary.technique_hunts.no_rule.length" class="mt-2">
            <summary class="text-sm text-[#2d7ab3] cursor-pointer">{{ selected.summary.technique_hunts.no_rule.length }} technique(s) with no ORION rule</summary>
            <ul class="text-xs text-gray-700 mt-2 space-y-0.5">
              <li v-for="t in selected.summary.technique_hunts.no_rule" :key="t.technique"><span class="font-mono">{{ t.technique }}</span> {{ t.name }}</li>
            </ul>
          </details>
        </div>

        <div v-if="selected.summary?.ioc?.checks?.length">
          <h3 class="font-bold mb-1">Indicator sweep</h3>
          <p class="text-xs text-gray-500 mb-2">
            {{ selected.summary.ioc.counts.ip || 0 }} addresses, {{ selected.summary.ioc.counts.domain || 0 }} domains, {{ selected.summary.ioc.counts.sha256 || 0 }} hashes.
          </p>
          <table class="w-full text-sm border">
            <thead class="bg-gray-100"><tr><th class="text-left px-3 py-2">Kind</th><th class="text-left px-3 py-2">SIEM</th><th class="text-left px-3 py-2">Could it check?</th><th class="text-left px-3 py-2">Matches</th></tr></thead>
            <tbody>
              <tr v-for="(c, i) in selected.summary.ioc.checks" :key="i" class="border-t">
                <td class="px-3 py-2">{{ c.kind }}</td>
                <td class="px-3 py-2">{{ c.connection }}</td>
                <td class="px-3 py-2"><span :class="c.status === 'checkable' ? 'text-green-700' : 'text-red-700'">{{ c.status }}</span><span v-if="c.reasons.length" class="block text-xs text-gray-500">{{ c.reasons[0] }}</span></td>
                <td class="px-3 py-2" :class="c.matches ? 'text-red-700 font-bold' : ''">{{ c.matches }}</td>
              </tr>
            </tbody>
          </table>
          <ul v-if="selected.summary.ioc.matches.length" class="mt-2 text-sm text-red-800 space-y-1">
            <li v-for="(m, i) in selected.summary.ioc.matches" :key="i"><span class="font-mono">{{ m.indicator }}</span> seen on {{ m.host || m.connection }} ({{ m.kind }})</li>
          </ul>
        </div>

        <div v-if="selected.summary?.kev">
          <h3 class="font-bold mb-1">Actively exploited vulnerabilities (CISA KEV)</h3>
          <p class="text-sm" :class="selected.summary.kev.exposure.status === 'checked' ? 'text-green-800' : 'text-amber-800'">
            {{ selected.summary.kev.exposure.status === 'checked'
              ? `Exposure checked: ${selected.summary.kev.exposure.matches.length} host(s) affected.`
              : `Exposure NOT checked: ${selected.summary.kev.exposure.reason}.` }}
          </p>
          <ul v-if="selected.summary.kev.exposure.matches.length" class="text-sm text-red-800 mt-1">
            <li v-for="(m, i) in selected.summary.kev.exposure.matches" :key="i">{{ m.cve }} on {{ m.host }} ({{ m.package }} {{ m.version }})</li>
          </ul>
          <p class="text-xs text-gray-500 mt-2">{{ selected.summary.kev.total }} CVEs on the list; {{ selected.summary.kev.new.length }} added in the window.</p>
          <ul class="text-xs text-gray-700 mt-1 space-y-0.5">
            <li v-for="e in selected.summary.kev.new.slice(0, 8)" :key="e.cve">
              <span class="font-mono">{{ e.cve }}</span> {{ e.vendor }} {{ e.product }}
              <span v-if="e.ransomware" class="text-red-700"> &middot; used by ransomware</span>
              <span v-if="e.epss !== null && e.epss !== undefined" class="text-gray-500"> &middot; exploit likelihood {{ (e.epss * 100).toFixed(0) }}%</span>
            </li>
          </ul>
        </div>

        <div v-if="selected.summary?.feeds">
          <h3 class="font-bold mb-1">Sources</h3>
          <ul class="text-xs text-gray-700 space-y-0.5">
            <li v-for="(m, name) in selected.summary.feeds" :key="name">
              <span class="font-mono">{{ name }}</span>: {{ m.status }}<span v-if="m.items !== null && m.items !== undefined"> ({{ m.items }} items)</span>
              <span v-if="m.error" class="text-red-700"> &middot; {{ m.error }}</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onBeforeUnmount, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import {
  listJobs, createJob, updateJob, runJobNow, listRuns, getRun, downloadFile,
  type Job, type RunBrief, type RunDetail,
} from '@/api/intel'

const auth = useAuthStore()
const route = useRoute()
const jobs = ref<Job[]>([])
const runs = reactive<Record<string, RunBrief[]>>({})
const selected = ref<RunDetail | null>(null)
const loading = ref(true)
const loadError = ref('')
const actionError = ref('')
const busy = ref(false)
let timer: number | undefined
let pollsLeft = 0

async function refreshRuns() {
  for (const j of jobs.value) runs[j.id] = (await listRuns(j.id)).slice(0, 8)
}

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    jobs.value = await listJobs()
    await refreshRuns()
    const requested = route.query.run as string | undefined
    if (requested) await openRun(requested)
  } catch (e: any) {
    loadError.value = e.response?.data?.detail || 'The ORION backend did not answer. Is it running on port 8000?'
  } finally {
    loading.value = false
  }
}

// After starting a check, look again every few seconds until it has finished.
function poll() {
  window.clearInterval(timer)
  pollsLeft = 60
  timer = window.setInterval(async () => {
    jobs.value = await listJobs()
    await refreshRuns()
    pollsLeft -= 1
    if (!jobs.value.some(j => j.running) || pollsLeft <= 0) window.clearInterval(timer)
  }, 4000)
}

async function act(fn: () => Promise<unknown>) {
  busy.value = true
  actionError.value = ''
  try {
    await fn()
    jobs.value = await listJobs()
    await refreshRuns()
  } catch (e: any) {
    actionError.value = e.response?.data?.detail || 'The action failed'
  } finally {
    busy.value = false
  }
}

const createDefault = () => act(() => createJob({}))
const toggle = (j: Job) => act(() => updateJob(j.id, { enabled: !j.enabled }))
const setInterval = (j: Job, hours: number) => act(() => updateJob(j.id, { interval_hours: hours }))
const runNow = (j: Job) => act(async () => { await runJobNow(j.id); poll() })

async function openRun(id: string) {
  try {
    selected.value = await getRun(id)
  } catch (e: any) {
    actionError.value = e.response?.data?.detail || 'Could not open that run'
  }
}

const report = (id: string) => downloadFile(`/jobs/runs/${id}/report.pdf`, 'threat-intel-report.pdf').catch(() => { actionError.value = 'The report could not be downloaded' })

function when(ts?: string | null): string {
  return ts ? new Date(ts).toLocaleString() : '-'
}

function verdictLabel(s: string): string {
  return ({ findings: 'possible match', clear: 'clear (within scope)', incomplete: 'incomplete', error: 'failed', running: 'running' } as Record<string, string>)[s] || s
}

function verdictBadge(s: string): string {
  return ({
    findings: 'bg-red-100 text-red-800', clear: 'bg-green-100 text-green-800',
    incomplete: 'bg-amber-100 text-amber-800', error: 'bg-amber-100 text-amber-800', running: 'bg-blue-100 text-blue-800',
  } as Record<string, string>)[s] || 'bg-gray-100 text-gray-700'
}

onMounted(load)
onBeforeUnmount(() => window.clearInterval(timer))
</script>
