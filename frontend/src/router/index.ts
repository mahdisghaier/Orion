import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import AppLayout from '@/components/AppLayout.vue'

const routes = [
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/LoginView.vue'),
    meta: { public: true }
  },
  {
    path: '/',
    component: AppLayout,
    redirect: '/findings',
    children: [
      {
        path: 'chat',
        name: 'chat',
        component: () => import('@/views/ChatView.vue'),
        meta: { requiresAuth: true }
      },
      {
        path: 'findings',
        name: 'findings',
        component: () => import('@/views/FindingsView.vue'),
        meta: { requiresAuth: true }
      },
      {
        path: 'findings/:id',
        name: 'finding-detail',
        component: () => import('@/views/FindingDetailView.vue'),
        meta: { requiresAuth: true }
      },
      {
        path: 'investigations',
        name: 'investigations',
        component: () => import('@/views/InvestigationsView.vue'),
        meta: { requiresAuth: true }
      },
      {
        path: 'investigations/:id',
        name: 'investigation-detail',
        component: () => import('@/views/InvestigationDetailView.vue'),
        meta: { requiresAuth: true }
      },
      {
        path: 'hunts',
        name: 'hunts',
        component: () => import('@/views/HuntsView.vue'),
        meta: { requiresAuth: true }
      },
      {
        path: 'hunts/new',
        name: 'hunt-create',
        component: () => import('@/views/HuntCreateView.vue'),
        meta: { requiresAuth: true }
      },
      {
        path: 'hunts/:id',
        name: 'hunt-detail',
        component: () => import('@/views/HuntDetailView.vue'),
        meta: { requiresAuth: true }
      },
      {
        path: 'siem',
        name: 'siem',
        component: () => import('@/views/SIEMView.vue'),
        meta: { requiresAuth: true, requiredRole: 'admin' }
      },
      {
        path: 'users',
        name: 'users',
        component: () => import('@/views/UsersView.vue'),
        meta: { requiresAuth: true, requiredRole: 'admin' }
      },
    ]
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: () => import('@/views/NotFoundView.vue')
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach(async (to, from, next) => {
  const auth = useAuthStore()

  // Only fetch user once per session (not on every navigation)
  if (!auth.checked) {
    await auth.fetchUser()
  }

  if (to.meta.requiresAuth && !auth.isAuthenticated) {
    next('/login')
  } else if (to.meta.public && auth.isAuthenticated) {
    next('/')
  } else if (to.meta.requiredRole && auth.role !== to.meta.requiredRole) {
    next('/')
  } else {
    next()
  }
})

export default router
