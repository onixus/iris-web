/**
 * IRIS Web — i18n (Internationalization)
 * Pure vanilla JS, no build step required.
 * Loaded in default.html before all page scripts.
 *
 * Usage anywhere in JS:
 *   iris_t('common.save')              // 'Сохранить' / 'Save'
 *   iris_t('common.rows', {count: 5})  // '5 записей'
 *   iris_set_locale('ru')              // switch at runtime
 */
(function (global) {
  'use strict';

  var STORAGE_KEY = 'iris_locale';

  var LOCALES = {
    en: {
      nav: {
        dashboard: 'Dashboard', cases: 'Cases', alerts: 'Alerts',
        search: 'Search', datastore: 'Datastore', activities: 'Activities',
        manage: 'Manage', logout: 'Logout', profile: 'My profile',
        mySettings: 'My settings', overview: 'Overview', welcome: 'Welcome page',
        investigation: 'Investigation', case: 'Case', dimTasks: 'DIM Tasks',
        manageCases: 'Manage cases', advanced: 'Advanced', help: 'Help',
        updatesAvailable: 'Updates are available for the server'
      },
      manage: {
        title: 'Administration', users: 'Users', groups: 'Groups',
        customers: 'Customers', modules: 'Modules', objects: 'Case Objects',
        attributes: 'Custom Attributes', templates: 'Report Templates',
        caseTemplates: 'Case Templates', serverSettings: 'Server settings',
        accessControl: 'Access control', audit: 'Audit'
      },
      cases: {
        title: 'Cases', newCase: 'New case', id: 'Case #', name: 'Name',
        status: 'Status', classification: 'Classification', owner: 'Owner',
        customer: 'Customer', openedAt: 'Opened', closedAt: 'Closed',
        severity: 'Severity', tlp: 'TLP', pap: 'PAP', summary: 'Summary',
        tasks: 'Tasks', timeline: 'Timeline', ioc: 'IOC', assets: 'Assets',
        notes: 'Notes', evidence: 'Evidence', graph: 'Graph', pipelines: 'Pipelines'
      },
      alerts: {
        title: 'Alerts', id: 'Alert ID', title_col: 'Title', source: 'Source',
        status: 'Status', severity: 'Severity', classification: 'Classification',
        owner: 'Owner', customer: 'Customer', createdAt: 'Created', updatedAt: 'Updated',
        merge: 'Merge into case', escalate: 'Escalate', dismiss: 'Dismiss'
      },
      tasks: {
        title: 'Tasks', name: 'Task name', status: 'Status', assignee: 'Assignee',
        addedAt: 'Added', dueDate: 'Due date', addTask: 'Add task',
        statusOpen: 'Open', statusDone: 'Done', statusInProg: 'In progress', statusToDo: 'To-do'
      },
      timeline: {
        title: 'Timeline', addEvent: 'Add event', eventDate: 'Date',
        eventTitle: 'Title', eventCategory: 'Category', eventColor: 'Color', eventRaw: 'Raw event'
      },
      notes: { title: 'Notes', newGroup: 'New group', newNote: 'New note', untitled: 'Untitled' },
      ioc: {
        title: 'Indicators of Compromise', value: 'Value', type: 'Type', tlp: 'TLP',
        description: 'Description', addIoc: 'Add IOC', importIoc: 'Import IOC',
        enrichIoc: 'Enrich', deleteIoc: 'Delete'
      },
      assets: {
        title: 'Assets', name: 'Name', type: 'Type', ip: 'IP / Hostname',
        description: 'Description', compromised: 'Compromised',
        addAsset: 'Add asset', importAssets: 'Import assets'
      },
      datastore: {
        title: 'Datastore', upload: 'Upload file', fileName: 'File name',
        size: 'Size', uploadedBy: 'Uploaded by', uploadedAt: 'Uploaded at',
        download: 'Download', delete: 'Delete'
      },
      dashboard: {
        title: 'Dashboard', openCases: 'Open cases', closedCases: 'Closed cases',
        openAlerts: 'Open alerts', recentActivity: 'Recent activity',
        casesOverTime: 'Cases over time', severityDist: 'Severity distribution'
      },
      common: {
        save: 'Save', cancel: 'Cancel', delete: 'Delete', edit: 'Edit',
        add: 'Add', close: 'Close', confirm: 'Confirm', loading: 'Loading…',
        error: 'Error', success: 'Success', warning: 'Warning', noData: 'No data available',
        search: 'Search…', actions: 'Actions', yes: 'Yes', no: 'No',
        createdAt: 'Created at', updatedAt: 'Updated at', description: 'Description',
        name: 'Name', type: 'Type', status: 'Status', unknown: 'Unknown',
        copy: 'Copy', export: 'Export', import: 'Import', refresh: 'Refresh',
        filter: 'Filter', rows: '{{count}} rows', page: 'Page {{current}} of {{total}}'
      },
      auth: {
        login: 'Sign in', logout: 'Sign out', username: 'Username', password: 'Password',
        forgotPassword: 'Forgot password?', loginFailed: 'Invalid credentials',
        mfa: 'Two-factor code', loginBtn: 'Sign in'
      },
      severity: {
        unspecified: 'Unspecified', informational: 'Informational',
        low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical'
      },
      tlp: { white: 'TLP:WHITE', green: 'TLP:GREEN', amber: 'TLP:AMBER', red: 'TLP:RED' }
    },

    ru: {
      nav: {
        dashboard: 'Дашборд',
        cases: 'Инциденты',
        alerts: 'Алерты',
        search: 'Поиск',
        datastore: 'Хранилище',
        activities: 'Активность',
        manage: 'Управление',
        logout: 'Выйти',
        profile: 'Мой профиль',
        mySettings: 'Мои настройки',
        overview: 'Обзор',
        welcome: 'Начальная страница',
        investigation: 'Расследование',
        case: 'Инцидент',
        dimTasks: 'Задачи DIM',
        manageCases: 'Управление инцидентами',
        advanced: 'Расширенные',
        help: 'Помощь',
        updatesAvailable: 'Доступны обновления сервера'
      },
      manage: {
        title: 'Администрирование',
        users: 'Пользователи',
        groups: 'Группы',
        customers: 'Клиенты',
        modules: 'Модули',
        objects: 'Объекты инцидента',
        attributes: 'Пользовательские атрибуты',
        templates: 'Шаблоны отчётов',
        caseTemplates: 'Шаблоны инцидентов',
        serverSettings: 'Настройки сервера',
        accessControl: 'Управление доступом',
        audit: 'Аудит'
      },
      cases: {
        title: 'Инциденты',
        newCase: 'Новый инцидент',
        id: 'Инцидент №',
        name: 'Название',
        status: 'Статус',
        classification: 'Классификация',
        owner: 'Ответственный',
        customer: 'Клиент',
        openedAt: 'Открыт',
        closedAt: 'Закрыт',
        severity: 'Серьёзность',
        tlp: 'TLP', pap: 'PAP',
        summary: 'Сводка',
        tasks: 'Задачи',
        timeline: 'Хронология',
        ioc: 'Индикаторы',
        assets: 'Активы',
        notes: 'Заметки',
        evidence: 'Доказательства',
        graph: 'Граф',
        pipelines: 'Пайплайны'
      },
      alerts: {
        title: 'Алерты',
        id: 'ID алерта',
        title_col: 'Заголовок',
        source: 'Источник',
        status: 'Статус',
        severity: 'Серьёзность',
        classification: 'Классификация',
        owner: 'Ответственный',
        customer: 'Клиент',
        createdAt: 'Создан',
        updatedAt: 'Обновлён',
        merge: 'Слить в инцидент',
        escalate: 'Эскалировать',
        dismiss: 'Отклонить'
      },
      tasks: {
        title: 'Задачи',
        name: 'Название задачи',
        status: 'Статус',
        assignee: 'Исполнитель',
        addedAt: 'Добавлена',
        dueDate: 'Срок',
        addTask: 'Добавить задачу',
        statusOpen: 'Открыта',
        statusDone: 'Выполнена',
        statusInProg: 'В работе',
        statusToDo: 'Запланирована'
      },
      timeline: {
        title: 'Хронология',
        addEvent: 'Добавить событие',
        eventDate: 'Дата',
        eventTitle: 'Заголовок',
        eventCategory: 'Категория',
        eventColor: 'Цвет',
        eventRaw: 'Сырое событие'
      },
      notes: {
        title: 'Заметки',
        newGroup: 'Новая группа',
        newNote: 'Новая заметка',
        untitled: 'Без названия'
      },
      ioc: {
        title: 'Индикаторы компрометации',
        value: 'Значение',
        type: 'Тип', tlp: 'TLP',
        description: 'Описание',
        addIoc: 'Добавить IOC',
        importIoc: 'Импорт IOC',
        enrichIoc: 'Обогатить',
        deleteIoc: 'Удалить'
      },
      assets: {
        title: 'Активы',
        name: 'Название',
        type: 'Тип',
        ip: 'IP / Имя хоста',
        description: 'Описание',
        compromised: 'Скомпрометирован',
        addAsset: 'Добавить актив',
        importAssets: 'Импорт активов'
      },
      datastore: {
        title: 'Хранилище файлов',
        upload: 'Загрузить файл',
        fileName: 'Имя файла',
        size: 'Размер',
        uploadedBy: 'Загружен пользователем',
        uploadedAt: 'Дата загрузки',
        download: 'Скачать',
        delete: 'Удалить'
      },
      dashboard: {
        title: 'Дашборд',
        openCases: 'Открытых инцидентов',
        closedCases: 'Закрытых инцидентов',
        openAlerts: 'Открытых алертов',
        recentActivity: 'Последняя активность',
        casesOverTime: 'Динамика инцидентов',
        severityDist: 'Распределение по серьёзности'
      },
      common: {
        save: 'Сохранить',
        cancel: 'Отмена',
        delete: 'Удалить',
        edit: 'Редактировать',
        add: 'Добавить',
        close: 'Закрыть',
        confirm: 'Подтвердить',
        loading: 'Загрузка…',
        error: 'Ошибка',
        success: 'Успешно',
        warning: 'Предупреждение',
        noData: 'Нет данных',
        search: 'Поиск…',
        actions: 'Действия',
        yes: 'Да', no: 'Нет',
        createdAt: 'Создано',
        updatedAt: 'Обновлено',
        description: 'Описание',
        name: 'Название',
        type: 'Тип',
        status: 'Статус',
        unknown: 'Неизвестно',
        copy: 'Копировать',
        export: 'Экспорт',
        import: 'Импорт',
        refresh: 'Обновить',
        filter: 'Фильтр',
        rows: '{{count}} записей',
        page: 'Страница {{current}} из {{total}}'
      },
      auth: {
        login: 'Войти',
        logout: 'Выйти',
        username: 'Имя пользователя',
        password: 'Пароль',
        forgotPassword: 'Забыли пароль?',
        loginFailed: 'Неверные учётные данные',
        mfa: 'Код 2FA',
        loginBtn: 'Войти'
      },
      severity: {
        unspecified: 'Не указана',
        informational: 'Информационная',
        low: 'Низкая',
        medium: 'Средняя',
        high: 'Высокая',
        critical: 'Критическая'
      },
      tlp: {
        white: 'TLP:БЕЛЫЙ',
        green: 'TLP:ЗЕЛЁНЫЙ',
        amber: 'TLP:ЯНТАРНЫЙ',
        red: 'TLP:КРАСНЫЙ'
      }
    }
  };

  /* ---- helpers ---- */
  function resolve(obj, key) {
    return key.split('.').reduce(function (o, k) {
      return (o && typeof o === 'object') ? o[k] : undefined;
    }, obj);
  }

  function interpolate(str, vars) {
    if (!vars) return str;
    return str.replace(/\{\{(\w+)\}\}/g, function (_, k) {
      return (vars[k] !== undefined) ? vars[k] : '{{' + k + '}}';
    });
  }

  /* ---- public API ---- */
  var currentLocale = (typeof localStorage !== 'undefined' &&
                       localStorage.getItem('iris_locale')) || 'en';

  function t(key, vars) {
    var lang = LOCALES[currentLocale] || LOCALES['en'];
    var text = resolve(lang, key) || resolve(LOCALES['en'], key) || key;
    return interpolate(text, vars);
  }

  function setLocale(lang) {
    if (!LOCALES[lang]) {
      console.warn('[i18n] Unknown locale: ' + lang);
      return;
    }
    currentLocale = lang;
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(STORAGE_KEY, lang);
    }
    // Update <html lang>
    document.documentElement.setAttribute('lang', lang);
    // Re-render all elements marked with data-i18n
    applyToDOM();
    // Refresh visible DataTables if loaded
    if (typeof $ !== 'undefined' && $.fn && $.fn.DataTable) {
      try { $.fn.DataTable.tables({ visible: true, api: true }).draw(false); } catch (_) {}
    }
    // Update switcher button states
    document.querySelectorAll('.iris-locale-btn').forEach(function (btn) {
      btn.classList.toggle('active', btn.dataset.locale === lang);
    });
  }

  function applyToDOM() {
    document.querySelectorAll('[data-i18n]').forEach(function (el) {
      el.textContent = t(el.getAttribute('data-i18n'));
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) {
      el.placeholder = t(el.getAttribute('data-i18n-placeholder'));
    });
    document.querySelectorAll('[data-i18n-title]').forEach(function (el) {
      el.title = t(el.getAttribute('data-i18n-title'));
    });
    var titleMeta = document.querySelector('[data-i18n-page-title]');
    if (titleMeta) {
      var suffix = titleMeta.getAttribute('data-i18n-page-title-suffix') || '';
      document.title = t(titleMeta.getAttribute('data-i18n-page-title')) + (suffix ? ' | ' + suffix : '');
    }
  }

  // Apply on DOMContentLoaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', applyToDOM);
  } else {
    applyToDOM();
  }

  // Expose globals
  global.iris_t           = t;
  global.iris_set_locale  = setLocale;
  global.iris_locale      = function () { return currentLocale; };
  global.IRIS_LOCALES     = LOCALES;

}(window));
