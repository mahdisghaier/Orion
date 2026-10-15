<template>
  <div class="flex h-screen bg-[#f5f8fc]">
    <aside class="w-64 bg-[#0a1628] text-white flex flex-col">
      <div class="p-6 border-b border-[#1a4a7a]">
        <h1 class="text-2xl font-black tracking-tight">ORION</h1>
        <p class="text-[10px] text-[#7a9bb8] mt-1 uppercase tracking-widest">Threat Hunting</p>
      </div>
      <nav class="flex-1 px-3 py-4 space-y-1">
        <RouterLink
          v-for="item in navItems"
          :key="item.path"
          :to="item.path"
          class="flex items-center px-3 py-2 rounded text-sm transition-colors"
          :class="isActive(item.path) ? 'bg-[#2d7ab3] text-white' : 'text-[#7a9bb8] hover:bg-[#1a4a7a]/50 hover:text-white'"
        >
          <component :is="item.icon" class="w-4 h-4 mr-3" />
          {{ item.label }}
          <span
            v-if="item.badge"
            class="ml-auto text-xs font-bold rounded-full px-2 py-0.5 text-white"
            :class="worst === 'critical' ? 'bg-red-600' : worst === 'warning' ? 'bg-amber-600' : 'bg-green-700'"
          >{{ item.badge }}</span>
        </RouterLink>
      </nav>
      <div class="p-3 border-t border-[#1a4a7a]">
        <div class="px-3 py-2">
          <p class="text-xs text-[#7a9bb8]">Signed in as</p>
          <p class="text-sm font-medium truncate">{{ auth.user?.email }}</p>
          <p class="text-[10px] text-[#4da8da] uppercase tracking-wider mt-1">{{ auth.user?.role }}</p>
        </div>
        <button
          @click="handleLogout"
          class="w-full mt-2 px-3 py-2 text-sm text-[#7a9bb8] hover:text-white hover:bg-[#1a4a7a]/50 rounded transition-colors text-left flex items-center"
        >
          <LogOut class="w-4 h-4 mr-3" />
          Sign out
        </button>
      </div>
    </aside>
    <main class="flex-1 overflow-auto">
      <router-view />
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onBeforeUnmount, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { Target, Bug, Server, Users, LogOut, MessageCircle, Search, ShieldAlert, Grid3x3, Bell } from 'lucide-vue-next'
import { notificationSummary } from '@/api/intel'

const auth = useAuthStore()
const route = useRoute()

const unread = ref(0)
const worst = ref<string | null>(null)
let badgeTimer: number | undefined

async function refreshBadge() {
  try {
    const s = await notificationSummary()
    unread.value = s.unread
    worst.value = s.worst
  } catch {
    // the badge is a convenience: a failed refresh must not disturb the page
  }
}

onMounted(() => {
  refreshBadge()
  badgeTimer = window.setInterval(refreshBadge, 60000)
})
onBeforeUnmount(() => window.clearInterval(badgeTimer))

const navItems = computed(() => {
  const items: { path: string; label: string; icon: any; badge?: number }[] = [
    { path: '/chat', label: 'AI Assistant', icon: MessageCircle },
    { path: '/findings', label: 'Findings', icon: Bug },
    { path: '/investigations', label: 'Investigations', icon: Search },
    { path: '/hunts', label: 'Hunts', icon: Target },
    { path: '/threat-intel', label: 'Threat intel', icon: ShieldAlert },
    { path: '/coverage', label: 'Coverage', icon: Grid3x3 },
    { path: '/notifications', label: 'Notifications', icon: Bell, badge: unread.value },
  ]
  if (auth.isAdmin) {
    items.push({ path: '/siem', label: 'SIEM Connections', icon: Server })
    items.push({ path: '/users', label: 'Users', icon: Users })
  }
  return items
})

function isActive(path: string) {
  return route.path === path || route.path.startsWith(path + '/')
}

async function handleLogout() {
  await auth.logout()
}
</script>
