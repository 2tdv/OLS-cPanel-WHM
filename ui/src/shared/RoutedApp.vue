<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import AppShell from './AppShell.vue'
import { useHashRouter } from './router.js'

// Both applications: the shell, navigation built from the app's route registry (routes.js), and the
// current view. Navigation labels are the catalog's `<catalog>.nav.<route name>`.
const props = defineProps({
  title: { type: String, required: true },
  catalog: { type: String, required: true },
  routes: { type: Array, required: true },
  fallback: { type: String, required: true },
})
const { t } = useI18n()
const { current } = useHashRouter(props.routes, props.fallback)
const nav = computed(() => props.routes.filter(r => !r.nav).map(r => ({ path: r.path, label: t(`${props.catalog}.nav.${r.name}`) })))
const active = computed(() => {
  const route = current.value.route
  return route.nav ? props.routes.find(r => r.name === route.nav).path : route.path
})
const routeKey = computed(() => `${current.value.route.name}/${JSON.stringify(current.value.params)}`)
</script>

<template>
  <AppShell :title="props.title" :nav="nav" :active="active" :route-key="routeKey">
    <component :is="current.route.view" :key="routeKey" :params="current.params" />
  </AppShell>
</template>
