/**
 * IRIS Web – i18n (Internationalization) module
 *
 * Usage:
 *   import { t, setLocale, locale } from '$lib/i18n';
 *
 *   // In Svelte:
 *   <span>{$t('nav.dashboard')}</span>
 *
 *   // In plain JS:
 *   import { get } from 'svelte/store';
 *   import { t } from '$lib/i18n';
 *   console.log(get(t)('nav.dashboard'));
 */

import { writable, derived, get } from 'svelte/store';
import en from './locales/en.js';
import ru from './locales/ru.js';

const LOCALES = { en, ru };
const STORAGE_KEY = 'iris_locale';

/** Active locale identifier ('en' | 'ru') */
export const locale = writable(
  (typeof localStorage !== 'undefined' && localStorage.getItem(STORAGE_KEY)) || 'en'
);

/** Persist locale choice */
locale.subscribe((lang) => {
  if (typeof localStorage !== 'undefined') {
    localStorage.setItem(STORAGE_KEY, lang);
  }
});

/**
 * Resolve a dot-notation key against a translations object.
 * Falls back to English, then to the key itself.
 */
function resolve(translations, key) {
  const parts = key.split('.');
  let node = translations;
  for (const part of parts) {
    if (node == null || typeof node !== 'object') return null;
    node = node[part];
  }
  return typeof node === 'string' ? node : null;
}

/**
 * Derived store: translate function bound to current locale.
 *
 * @param {string} key  – dot-notation key, e.g. 'nav.cases'
 * @param {Object} [vars] – optional interpolation map: { count: 5 }
 * @returns {string}
 */
export const t = derived(locale, ($locale) => {
  return (key, vars = {}) => {
    const translations = LOCALES[$locale] ?? LOCALES['en'];
    let text = resolve(translations, key) ?? resolve(LOCALES['en'], key) ?? key;
    // Simple variable interpolation: {{varName}}
    Object.entries(vars).forEach(([k, v]) => {
      text = text.replaceAll(`{{${k}}}`, v);
    });
    return text;
  };
});

/**
 * Imperatively translate (outside Svelte reactive context).
 * @param {string} key
 * @param {Object} [vars]
 * @returns {string}
 */
export function translate(key, vars = {}) {
  return get(t)(key, vars);
}

/** Change the active locale */
export function setLocale(lang) {
  if (LOCALES[lang]) {
    locale.set(lang);
  } else {
    console.warn(`[i18n] Unknown locale: "${lang}". Supported: ${Object.keys(LOCALES).join(', ')}`);
  }
}

/** List of all supported locales with display names */
export const SUPPORTED_LOCALES = [
  { code: 'en', label: 'English' },
  { code: 'ru', label: 'Русский' },
];
