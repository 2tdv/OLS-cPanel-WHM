<script setup>
import { useI18n } from 'vue-i18n'
import RoutedApp from '../shared/RoutedApp.vue'
import { fallback, routes } from './routes.js'

// cPanel application (the logged-in account only, plugins/cpanel/index.live.php). Views: routes.js.
const { t } = useI18n()
</script>

<template>
  <RoutedApp :title="t('cpanel.title')" catalog="cpanel" :routes="routes" :fallback="fallback" />
</template>
