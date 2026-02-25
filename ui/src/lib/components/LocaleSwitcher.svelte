<script>
  import { locale, setLocale, SUPPORTED_LOCALES } from '$lib/i18n';

  /** Visual style: 'dropdown' | 'buttons' */
  export let style = 'dropdown';
</script>

{#if style === 'buttons'}
  <div class="locale-switcher-buttons" role="group" aria-label="Language switcher">
    {#each SUPPORTED_LOCALES as loc}
      <button
        class="locale-btn"
        class:active={$locale === loc.code}
        on:click={() => setLocale(loc.code)}
        aria-pressed={$locale === loc.code}
        title={loc.label}
      >
        {loc.code.toUpperCase()}
      </button>
    {/each}
  </div>
{:else}
  <select
    class="locale-select form-control form-control-sm"
    bind:value={$locale}
    on:change={(e) => setLocale(e.target.value)}
    aria-label="Language"
  >
    {#each SUPPORTED_LOCALES as loc}
      <option value={loc.code}>{loc.label}</option>
    {/each}
  </select>
{/if}

<style>
  .locale-switcher-buttons {
    display: inline-flex;
    gap: 4px;
  }

  .locale-btn {
    padding: 2px 8px;
    border: 1px solid #ccc;
    border-radius: 4px;
    background: transparent;
    cursor: pointer;
    font-size: 12px;
    font-weight: 500;
    color: #aaa;
    transition: all 0.15s;
  }

  .locale-btn:hover {
    border-color: #888;
    color: #fff;
  }

  .locale-btn.active {
    border-color: #4a90d9;
    color: #4a90d9;
    background: rgba(74, 144, 217, 0.1);
  }

  .locale-select {
    max-width: 120px;
    display: inline-block;
  }
</style>
