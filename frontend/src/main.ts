import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import './assets/main.css'

// [explain] Creates the Vue application: the program that runs inside the browser and draws the pages.
const app = createApp(App)
app.use(createPinia())
app.use(router)
app.mount('#app')
