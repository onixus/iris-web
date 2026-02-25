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
        manage: 'Manage', logout: 'Logout', profile: 'My profile'
      },
      manage: {
        title: 'Administration', users: 'Users', groups: 'Groups',
        customers: 'Customers', modules: 'Modules', objects: 'Object types',
        attributes: 'Attributes', templates: 'Report templates',
        caseTemplates: 'Case templates', serverSettings: 'Server settings', audit: 'Audit'
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
        add: 'Add', close: 'Close', confirm: 'Confirm', loading: 'Loading\u2026',
        error: 'Error', success: 'Success', warning: 'Warning', noData: 'No data available',
        search: 'Search\u2026', actions: 'Actions', yes: 'Yes', no: 'No',
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
        dashboard: '\u0414\u0430\u0448\u0431\u043e\u0440\u0434',
        cases: '\u0418\u043d\u0446\u0438\u0434\u0435\u043d\u0442\u044b',
        alerts: '\u0410\u043b\u0435\u0440\u0442\u044b',
        search: '\u041f\u043e\u0438\u0441\u043a',
        datastore: '\u0425\u0440\u0430\u043d\u0438\u043b\u0438\u0449\u0435',
        activities: '\u0410\u043a\u0442\u0438\u0432\u043d\u043e\u0441\u0442\u044c',
        manage: '\u0423\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u0438\u0435',
        logout: '\u0412\u044b\u0439\u0442\u0438',
        profile: '\u041c\u043e\u0439 \u043f\u0440\u043e\u0444\u0438\u043b\u044c'
      },
      manage: {
        title: '\u0410\u0434\u043c\u0438\u043d\u0438\u0441\u0442\u0440\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u0435',
        users: '\u041f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u0438',
        groups: '\u0413\u0440\u0443\u043f\u043f\u044b',
        customers: '\u041a\u043b\u0438\u0435\u043d\u0442\u044b',
        modules: '\u041c\u043e\u0434\u0443\u043b\u0438',
        objects: '\u0422\u0438\u043f\u044b \u043e\u0431\u044a\u0435\u043a\u0442\u043e\u0432',
        attributes: '\u0410\u0442\u0440\u0438\u0431\u0443\u0442\u044b',
        templates: '\u0428\u0430\u0431\u043b\u043e\u043d\u044b \u043e\u0442\u0447\u0451\u0442\u043e\u0432',
        caseTemplates: '\u0428\u0430\u0431\u043b\u043e\u043d\u044b \u0438\u043d\u0446\u0438\u0434\u0435\u043d\u0442\u043e\u0432',
        serverSettings: '\u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438 \u0441\u0435\u0440\u0432\u0435\u0440\u0430',
        audit: '\u0410\u0443\u0434\u0438\u0442'
      },
      cases: {
        title: '\u0418\u043d\u0446\u0438\u0434\u0435\u043d\u0442\u044b',
        newCase: '\u041d\u043e\u0432\u044b\u0439 \u0438\u043d\u0446\u0438\u0434\u0435\u043d\u0442',
        id: '\u0418\u043d\u0446\u0438\u0434\u0435\u043d\u0442 \u2116',
        name: '\u041d\u0430\u0437\u0432\u0430\u043d\u0438\u0435',
        status: '\u0421\u0442\u0430\u0442\u0443\u0441',
        classification: '\u041a\u043b\u0430\u0441\u0441\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u044f',
        owner: '\u041e\u0442\u0432\u0435\u0442\u0441\u0442\u0432\u0435\u043d\u043d\u044b\u0439',
        customer: '\u041a\u043b\u0438\u0435\u043d\u0442',
        openedAt: '\u041e\u0442\u043a\u0440\u044b\u0442',
        closedAt: '\u0417\u0430\u043a\u0440\u044b\u0442',
        severity: '\u0421\u0435\u0440\u044c\u0451\u0437\u043d\u043e\u0441\u0442\u044c',
        tlp: 'TLP', pap: 'PAP',
        summary: '\u0421\u0432\u043e\u0434\u043a\u0430',
        tasks: '\u0417\u0430\u0434\u0430\u0447\u0438',
        timeline: '\u0425\u0440\u043e\u043d\u043e\u043b\u043e\u0433\u0438\u044f',
        ioc: '\u0418\u043d\u0434\u0438\u043a\u0430\u0442\u043e\u0440\u044b',
        assets: '\u0410\u043a\u0442\u0438\u0432\u044b',
        notes: '\u0417\u0430\u043c\u0435\u0442\u043a\u0438',
        evidence: '\u0414\u043e\u043a\u0430\u0437\u0430\u0442\u0435\u043b\u044c\u0441\u0442\u0432\u0430',
        graph: '\u0413\u0440\u0430\u0444',
        pipelines: '\u041f\u0430\u0439\u043f\u043b\u0430\u0439\u043d\u044b'
      },
      alerts: {
        title: '\u0410\u043b\u0435\u0440\u0442\u044b',
        id: 'ID \u0430\u043b\u0435\u0440\u0442\u0430',
        title_col: '\u0417\u0430\u0433\u043e\u043b\u043e\u0432\u043e\u043a',
        source: '\u0418\u0441\u0442\u043e\u0447\u043d\u0438\u043a',
        status: '\u0421\u0442\u0430\u0442\u0443\u0441',
        severity: '\u0421\u0435\u0440\u044c\u0451\u0437\u043d\u043e\u0441\u0442\u044c',
        classification: '\u041a\u043b\u0430\u0441\u0441\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u044f',
        owner: '\u041e\u0442\u0432\u0435\u0442\u0441\u0442\u0432\u0435\u043d\u043d\u044b\u0439',
        customer: '\u041a\u043b\u0438\u0435\u043d\u0442',
        createdAt: '\u0421\u043e\u0437\u0434\u0430\u043d',
        updatedAt: '\u041e\u0431\u043d\u043e\u0432\u043b\u0451\u043d',
        merge: '\u0421\u043b\u0438\u0442\u044c \u0432 \u0438\u043d\u0446\u0438\u0434\u0435\u043d\u0442',
        escalate: '\u042d\u0441\u043a\u0430\u043b\u0438\u0440\u043e\u0432\u0430\u0442\u044c',
        dismiss: '\u041e\u0442\u043a\u043b\u043e\u043d\u0438\u0442\u044c'
      },
      tasks: {
        title: '\u0417\u0430\u0434\u0430\u0447\u0438',
        name: '\u041d\u0430\u0437\u0432\u0430\u043d\u0438\u0435 \u0437\u0430\u0434\u0430\u0447\u0438',
        status: '\u0421\u0442\u0430\u0442\u0443\u0441',
        assignee: '\u0418\u0441\u043f\u043e\u043b\u043d\u0438\u0442\u0435\u043b\u044c',
        addedAt: '\u0414\u043e\u0431\u0430\u0432\u043b\u0435\u043d\u0430',
        dueDate: '\u0421\u0440\u043e\u043a',
        addTask: '\u0414\u043e\u0431\u0430\u0432\u0438\u0442\u044c \u0437\u0430\u0434\u0430\u0447\u0443',
        statusOpen: '\u041e\u0442\u043a\u0440\u044b\u0442\u0430',
        statusDone: '\u0412\u044b\u043f\u043e\u043b\u043d\u0435\u043d\u0430',
        statusInProg: '\u0412 \u0440\u0430\u0431\u043e\u0442\u0435',
        statusToDo: '\u0417\u0430\u043f\u043b\u0430\u043d\u0438\u0440\u043e\u0432\u0430\u043d\u0430'
      },
      timeline: {
        title: '\u0425\u0440\u043e\u043d\u043e\u043b\u043e\u0433\u0438\u044f',
        addEvent: '\u0414\u043e\u0431\u0430\u0432\u0438\u0442\u044c \u0441\u043e\u0431\u044b\u0442\u0438\u0435',
        eventDate: '\u0414\u0430\u0442\u0430',
        eventTitle: '\u0417\u0430\u0433\u043e\u043b\u043e\u0432\u043e\u043a',
        eventCategory: '\u041a\u0430\u0442\u0435\u0433\u043e\u0440\u0438\u044f',
        eventColor: '\u0426\u0432\u0435\u0442',
        eventRaw: '\u0421\u044b\u0440\u043e\u0435 \u0441\u043e\u0431\u044b\u0442\u0438\u0435'
      },
      notes: {
        title: '\u0417\u0430\u043c\u0435\u0442\u043a\u0438',
        newGroup: '\u041d\u043e\u0432\u0430\u044f \u0433\u0440\u0443\u043f\u043f\u0430',
        newNote: '\u041d\u043e\u0432\u0430\u044f \u0437\u0430\u043c\u0435\u0442\u043a\u0430',
        untitled: '\u0411\u0435\u0437 \u043d\u0430\u0437\u0432\u0430\u043d\u0438\u044f'
      },
      ioc: {
        title: '\u0418\u043d\u0434\u0438\u043a\u0430\u0442\u043e\u0440\u044b \u043a\u043e\u043c\u043f\u0440\u043e\u043c\u0435\u0442\u0430\u0446\u0438\u0438',
        value: '\u0417\u043d\u0430\u0447\u0435\u043d\u0438\u0435',
        type: '\u0422\u0438\u043f', tlp: 'TLP',
        description: '\u041e\u043f\u0438\u0441\u0430\u043d\u0438\u0435',
        addIoc: '\u0414\u043e\u0431\u0430\u0432\u0438\u0442\u044c IOC',
        importIoc: '\u0418\u043c\u043f\u043e\u0440\u0442 IOC',
        enrichIoc: '\u041e\u0431\u043e\u0433\u0430\u0442\u0438\u0442\u044c',
        deleteIoc: '\u0423\u0434\u0430\u043b\u0438\u0442\u044c'
      },
      assets: {
        title: '\u0410\u043a\u0442\u0438\u0432\u044b',
        name: '\u041d\u0430\u0437\u0432\u0430\u043d\u0438\u0435',
        type: '\u0422\u0438\u043f',
        ip: 'IP / \u0418\u043c\u044f \u0445\u043e\u0441\u0442\u0430',
        description: '\u041e\u043f\u0438\u0441\u0430\u043d\u0438\u0435',
        compromised: '\u0421\u043a\u043e\u043c\u043f\u0440\u043e\u043c\u0435\u0442\u0438\u0440\u043e\u0432\u0430\u043d',
        addAsset: '\u0414\u043e\u0431\u0430\u0432\u0438\u0442\u044c \u0430\u043a\u0442\u0438\u0432',
        importAssets: '\u0418\u043c\u043f\u043e\u0440\u0442 \u0430\u043a\u0442\u0438\u0432\u043e\u0432'
      },
      datastore: {
        title: '\u0425\u0440\u0430\u043d\u0438\u043b\u0438\u0449\u0435 \u0444\u0430\u0439\u043b\u043e\u0432',
        upload: '\u0417\u0430\u0433\u0440\u0443\u0437\u0438\u0442\u044c \u0444\u0430\u0439\u043b',
        fileName: '\u0418\u043c\u044f \u0444\u0430\u0439\u043b\u0430',
        size: '\u0420\u0430\u0437\u043c\u0435\u0440',
        uploadedBy: '\u0417\u0430\u0433\u0440\u0443\u0436\u0435\u043d \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u0435\u043c',
        uploadedAt: '\u0414\u0430\u0442\u0430 \u0437\u0430\u0433\u0440\u0443\u0437\u043a\u0438',
        download: '\u0421\u043a\u0430\u0447\u0430\u0442\u044c',
        delete: '\u0423\u0434\u0430\u043b\u0438\u0442\u044c'
      },
      dashboard: {
        title: '\u0414\u0430\u0448\u0431\u043e\u0440\u0434',
        openCases: '\u041e\u0442\u043a\u0440\u044b\u0442\u044b\u0445 \u0438\u043d\u0446\u0438\u0434\u0435\u043d\u0442\u043e\u0432',
        closedCases: '\u0417\u0430\u043a\u0440\u044b\u0442\u044b\u0445 \u0438\u043d\u0446\u0438\u0434\u0435\u043d\u0442\u043e\u0432',
        openAlerts: '\u041e\u0442\u043a\u0440\u044b\u0442\u044b\u0445 \u0430\u043b\u0435\u0440\u0442\u043e\u0432',
        recentActivity: '\u041f\u043e\u0441\u043b\u0435\u0434\u043d\u044f\u044f \u0430\u043a\u0442\u0438\u0432\u043d\u043e\u0441\u0442\u044c',
        casesOverTime: '\u0414\u0438\u043d\u0430\u043c\u0438\u043a\u0430 \u0438\u043d\u0446\u0438\u0434\u0435\u043d\u0442\u043e\u0432',
        severityDist: '\u0420\u0430\u0441\u043f\u0440\u0435\u0434\u0435\u043b\u0435\u043d\u0438\u0435 \u043f\u043e \u0441\u0435\u0440\u044c\u0451\u0437\u043d\u043e\u0441\u0442\u0438'
      },
      common: {
        save: '\u0421\u043e\u0445\u0440\u0430\u043d\u0438\u0442\u044c',
        cancel: '\u041e\u0442\u043c\u0435\u043d\u0430',
        delete: '\u0423\u0434\u0430\u043b\u0438\u0442\u044c',
        edit: '\u0420\u0435\u0434\u0430\u043a\u0442\u0438\u0440\u043e\u0432\u0430\u0442\u044c',
        add: '\u0414\u043e\u0431\u0430\u0432\u0438\u0442\u044c',
        close: '\u0417\u0430\u043a\u0440\u044b\u0442\u044c',
        confirm: '\u041f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u044c',
        loading: '\u0417\u0430\u0433\u0440\u0443\u0437\u043a\u0430\u2026',
        error: '\u041e\u0448\u0438\u0431\u043a\u0430',
        success: '\u0423\u0441\u043f\u0435\u0448\u043d\u043e',
        warning: '\u041f\u0440\u0435\u0434\u0443\u043f\u0440\u0435\u0436\u0434\u0435\u043d\u0438\u0435',
        noData: '\u041d\u0435\u0442 \u0434\u0430\u043d\u043d\u044b\u0445',
        search: '\u041f\u043e\u0438\u0441\u043a\u2026',
        actions: '\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u044f',
        yes: '\u0414\u0430', no: '\u041d\u0435\u0442',
        createdAt: '\u0421\u043e\u0437\u0434\u0430\u043d\u043e',
        updatedAt: '\u041e\u0431\u043d\u043e\u0432\u043b\u0435\u043d\u043e',
        description: '\u041e\u043f\u0438\u0441\u0430\u043d\u0438\u0435',
        name: '\u041d\u0430\u0437\u0432\u0430\u043d\u0438\u0435',
        type: '\u0422\u0438\u043f',
        status: '\u0421\u0442\u0430\u0442\u0443\u0441',
        unknown: '\u041d\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043d\u043e',
        copy: '\u041a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c',
        export: '\u042d\u043a\u0441\u043f\u043e\u0440\u0442',
        import: '\u0418\u043c\u043f\u043e\u0440\u0442',
        refresh: '\u041e\u0431\u043d\u043e\u0432\u0438\u0442\u044c',
        filter: '\u0424\u0438\u043b\u044c\u0442\u0440',
        rows: '{{count}} \u0437\u0430\u043f\u0438\u0441\u0435\u0439',
        page: '\u0421\u0442\u0440\u0430\u043d\u0438\u0446\u0430 {{current}} \u0438\u0437 {{total}}'
      },
      auth: {
        login: '\u0412\u043e\u0439\u0442\u0438',
        logout: '\u0412\u044b\u0439\u0442\u0438',
        username: '\u0418\u043c\u044f \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u044f',
        password: '\u041f\u0430\u0440\u043e\u043b\u044c',
        forgotPassword: '\u0417\u0430\u0431\u044b\u043b\u0438 \u043f\u0430\u0440\u043e\u043b\u044c?',
        loginFailed: '\u041d\u0435\u0432\u0435\u0440\u043d\u044b\u0435 \u0443\u0447\u0451\u0442\u043d\u044b\u0435 \u0434\u0430\u043d\u043d\u044b\u0435',
        mfa: '\u041a\u043e\u0434 2FA',
        loginBtn: '\u0412\u043e\u0439\u0442\u0438'
      },
      severity: {
        unspecified: '\u041d\u0435 \u0443\u043a\u0430\u0437\u0430\u043d\u0430',
        informational: '\u0418\u043d\u0444\u043e\u0440\u043c\u0430\u0446\u0438\u043e\u043d\u043d\u0430\u044f',
        low: '\u041d\u0438\u0437\u043a\u0430\u044f',
        medium: '\u0421\u0440\u0435\u0434\u043d\u044f\u044f',
        high: '\u0412\u044b\u0441\u043e\u043a\u0430\u044f',
        critical: '\u041a\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043a\u0430\u044f'
      },
      tlp: {
        white: 'TLP:\u0411\u0415\u041b\u042b\u0419',
        green: 'TLP:\u0417\u0415\u041b\u0401\u041d\u042b\u0419',
        amber: 'TLP:\u042f\u041d\u0422\u0410\u0420\u041d\u042b\u0419',
        red: 'TLP:\u041a\u0420\u0410\u0421\u041d\u042b\u0419'
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

  /**
   * Apply translations to elements with data-i18n attribute.
   * <span data-i18n="common.save"></span>  → sets textContent
   * <input data-i18n-placeholder="common.search"> → sets placeholder
   * <button data-i18n-title="common.edit"> → sets title
   */
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
