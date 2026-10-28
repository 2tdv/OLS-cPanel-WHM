import { createApp, defineAsyncComponent, h } from 'vue'
import 'element-plus/theme-chalk/base.css'
import {
  ElAlert, ElButton, ElCheckbox, ElCheckboxGroup, ElCollapse, ElCollapseItem, ElConfigProvider, ElDialog, ElEmpty, ElInput, ElOption, ElPagination,
  ElPopconfirm, ElRadio, ElRadioButton, ElRadioGroup, ElResult, ElSelect, ElSkeleton, ElSwitch, ElTable, ElTableColumn,
} from 'element-plus'
// Only the components the plugins use, each with its own styles (UIX-02: the full library and
// stylesheet made the first view miss the 1.5 s budget in the 2026-10-22 human review).
import 'element-plus/es/components/alert/style/css'
import 'element-plus/es/components/button/style/css'
import 'element-plus/es/components/checkbox/style/css'
import 'element-plus/es/components/checkbox-group/style/css'
import 'element-plus/es/components/collapse/style/css'
import 'element-plus/es/components/collapse-item/style/css'
import 'element-plus/es/components/config-provider/style/css'
import 'element-plus/es/components/dialog/style/css'
import 'element-plus/es/components/empty/style/css'
import 'element-plus/es/components/input/style/css'
import 'element-plus/es/components/option/style/css'
import 'element-plus/es/components/pagination/style/css'
import 'element-plus/es/components/popconfirm/style/css'
import 'element-plus/es/components/radio/style/css'
import 'element-plus/es/components/radio-button/style/css'
import 'element-plus/es/components/radio-group/style/css'
import 'element-plus/es/components/result/style/css'
import 'element-plus/es/components/select/style/css'
import 'element-plus/es/components/skeleton/style/css'
import 'element-plus/es/components/switch/style/css'
import 'element-plus/es/components/table/style/css'
import 'element-plus/es/components/table-column/style/css'
import './theme.css'
import { i18n } from './i18n.js'
import { CLIENT_KEY, createClient } from './api.js'
import ViewFallback from './ViewFallback.vue'

// ElRadio installs the radio group and the radio button too (their own exports are no-op installs).
export const COMPONENTS = [
  ElAlert, ElButton, ElCheckbox, ElCheckboxGroup, ElCollapse, ElCollapseItem, ElConfigProvider, ElDialog, ElEmpty, ElInput, ElOption, ElPagination,
  ElPopconfirm, ElRadio, ElRadioButton, ElRadioGroup, ElResult, ElSelect, ElSkeleton, ElSwitch, ElTable, ElTableColumn,
]

/** A view loaded on first use (its own chunk), with the shared loading and failure states. */
export function lazyView(loader) {
  return defineAsyncComponent({
    loader,
    delay: 150,
    timeout: 20000,
    loadingComponent: ViewFallback,
    errorComponent: { name: 'ViewLoadFailed', render: () => h(ViewFallback, { failed: true }) },
  })
}

/**
 * Keyboard access to scrollable regions (WCAG 2.1.1): Element Plus scrolls tables inside a wrapper that is not
 * focusable, so a keyboard user could not scroll a table wider or taller than its box. A wrapper that really
 * overflows gets tabindex="0" (the arrow keys then scroll it); one that does not stays out of the tab order.
 * The same pass names the page-size selector of every pagination (Element Plus renders it without a label, WCAG 4.1.2).
 */
export function watchRegions(root) {
  let queued = false
  const mark = () => {
    queued = false
    for (const el of root.querySelectorAll('.el-scrollbar__wrap')) {
      const overflows = el.scrollHeight > el.clientHeight + 1 || el.scrollWidth > el.clientWidth + 1
      if (overflows && !el.hasAttribute('tabindex')) el.setAttribute('tabindex', '0')
      else if (!overflows && el.getAttribute('tabindex') === '0') el.removeAttribute('tabindex')
    }
    for (const el of root.querySelectorAll('.el-pagination__sizes .el-select__input:not([aria-label])')) el.setAttribute('aria-label', i18n.global.t('table.pageSize'))
  }
  // Tables settle their layout after the DOM change (a resize observer inside Element Plus), so the pass also runs a moment later.
  const queue = () => { if (!queued) { queued = true; requestAnimationFrame(mark); setTimeout(mark, 400) } }
  new MutationObserver(queue).observe(root, { childList: true, subtree: true })
  window.addEventListener('resize', queue)
  queue()
}

// The host page renders <div id="ols-cpanel-app" data-endpoint="..."> inside the WHM or cPanel chrome.
export function mount(App) {
  const el = document.getElementById('ols-cpanel-app')
  if (!el) return
  const app = createApp(App)
  for (const component of COMPONENTS) app.use(component)
  app.use(i18n)
  app.provide(CLIENT_KEY, createClient(el.dataset.endpoint || ''))
  app.mount(el)
  watchRegions(el)
}
