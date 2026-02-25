# IRIS Web – Internationalization (i18n)

This module provides runtime multi-language support for IRIS Web UI.

## Supported languages

| Code | Language |
|------|----------|
| `en` | English (default) |
| `ru` | Russian / Русский |

---

## Architecture

```
ui/src/lib/i18n/
├── index.js            # Core: stores, t(), setLocale()
├── jquery-bridge.js    # Global window.iris_t() for legacy jQuery pages
├── README.md           # This file
└── locales/
    ├── en.js           # English strings
    └── ru.js           # Russian strings
```

---

## Usage in Svelte components

```svelte
<script>
  import { t } from '$lib/i18n';
</script>

<button>{$t('common.save')}</button>
<h1>{$t('cases.title')}</h1>
```

With interpolation:
```svelte
<span>{$t('common.rows', { count: total })}</span>
<!-- renders: '42 записей' (ru) or '42 rows' (en) -->
```

---

## Usage in legacy jQuery pages (`ui/src/pages/*.js`)

The `jquery-bridge.js` module exposes `window.iris_t()` globally:

```js
// In any page JS loaded after the bridge:
const saveLabel = iris_t('common.save');      // 'Сохранить' or 'Save'
const msg       = iris_t('alerts.dismiss');   // 'Отклонить' or 'Dismiss'
```

Change language at runtime:
```js
iris_setLocale('ru');  // switch to Russian
iris_setLocale('en');  // switch to English
```

---

## Language switcher component

```svelte
<script>
  import LocaleSwitcher from '$lib/components/LocaleSwitcher.svelte';
</script>

<!-- Dropdown (default) -->
<LocaleSwitcher />

<!-- Toggle buttons -->
<LocaleSwitcher style="buttons" />
```

---

## Adding a new language

1. Create `ui/src/lib/i18n/locales/XX.js` (copy `en.js` as template)
2. Register it in `index.js`:
   ```js
   import XX from './locales/XX.js';
   const LOCALES = { en, ru, XX };
   ```
3. Add to `SUPPORTED_LOCALES`:
   ```js
   { code: 'XX', label: 'Your Language' }
   ```

---

## Translation keys structure

| Namespace | Description |
|-----------|-------------|
| `nav.*` | Navigation sidebar & top bar |
| `manage.*` | Admin section labels |
| `cases.*` | Case management |
| `alerts.*` | Alert management |
| `ioc.*` | Indicators of Compromise |
| `assets.*` | Asset management |
| `tasks.*` | Task management |
| `timeline.*` | Timeline events |
| `notes.*` | Notes & groups |
| `datastore.*` | File datastore |
| `dashboard.*` | Dashboard widgets |
| `common.*` | Shared UI labels |
| `auth.*` | Authentication screens |
| `severity.*` | Severity levels |
| `tlp.*` | TLP labels |
