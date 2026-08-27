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
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { Target, Bug, Server, Users, LogOut, MessageCircle } from 'lucide-vue-next'

const auth = useAuthStore()
const route = useRoute()

const navItems = computed(() => {
  const items = [
    { path: '/chat', label: 'AI Assistant', icon: MessageCircle },
    { path: '/findings', label: 'Findings', icon: Bug },
    { path: '/hunts', label: 'Hunts', icon: Target },
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
