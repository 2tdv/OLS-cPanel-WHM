<script setup>
import { useI18n } from 'vue-i18n'
import RoutedApp from '../shared/RoutedApp.vue'
import { fallback, routes } from './routes.js'

// WHM application (root only, plugins/whm/index.cgi). Views and navigation: routes.js.
const { t } = useI18n()
</script>

<template>
  <RoutedApp :title="t('whm.title')" catalog="whm" :routes="routes" :fallback="fallback" />
</template>
