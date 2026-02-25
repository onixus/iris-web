/**
 * i18n bridge for legacy jQuery-based pages (ui/src/pages/*.js)
 *
 * This module exposes a global `iris_t()` function so that plain JS
 * files that cannot import ES modules can still use translations.
 *
 * Include this script before any page script that needs translations.
 *
 * Usage in legacy JS:
 *   const label = iris_t('common.save');       // 'Сохранить' / 'Save'
 *   const msg   = iris_t('common.rows', { count: 42 }); // '42 записей'
 */

import { get } from 'svelte/store';
import { t, locale, setLocale, SUPPORTED_LOCALES } from './index.js';

// Expose globally for legacy scripts
if (typeof window !== 'undefined') {
  /** Translate a key. Falls back to English, then to the key itself. */
  window.iris_t = (key, vars = {}) => get(t)(key, vars);

  /** Change locale from legacy JS */
  window.iris_setLocale = setLocale;

  /** Current locale value */
  window.iris_locale = locale;

  /** Supported locales array */
  window.iris_locales = SUPPORTED_LOCALES;

  // Keep window.iris_locale_value in sync for polling-based legacy code
  locale.subscribe((lang) => {
    window.iris_locale_value = lang;
  });

  // Re-render DataTables headers on locale change (if DataTables is loaded)
  locale.subscribe(() => {
    if (typeof $ !== 'undefined' && $.fn && $.fn.DataTable) {
      try {
        $.fn.DataTable.tables({ visible: true, api: true }).draw(false);
      } catch (_) {
        // DataTables not yet initialised – ignore
      }
    }
  });
}

export { t, locale, setLocale, SUPPORTED_LOCALES };
