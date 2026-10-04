// ==========================================================================
// Jev Page Safety — content script
// Собирает структуру страницы, локально определяет потенциально опасные
// элементы и подсвечивает их прямо на странице.
// ==========================================================================

// id находки -> живой DOM-элемент (для подсветки и прокрутки к элементу).
const jevFindingElements = new Map();
// Оригинальные значения атрибута title, чтобы корректно их восстановить.
const jevOriginalTitles = new WeakMap();
// Сквозной счётчик идентификаторов находок.
let jevFindingSeq = 0;

// Порядок важности для сортировки находок.
const JEV_SEVERITY_ORDER = { critical: 3, high: 2, medium: 1, low: 0 };
// Максимальное число находок, показываемых на странице и в popup.
const JEV_MAX_FINDINGS = 40;
// Находки, показанные в данный момент (для синхронизации панели после удаления).
let jevCurrentFindings = [];
// Сводка по структуре последней просканированной страницы (для панели на странице).
let jevLastPageSummary = null;

// --------------------------------------------------------------------------
// Вспомогательные функции
// --------------------------------------------------------------------------

// Origin ссылки (с учётом относительных путей) или '' при ошибке разбора.
function jevGetOrigin(url) {
  try {
    return new URL(url, window.location.href).origin;
  } catch (e) {
    return '';
  }
}

// Ведёт ли ссылка на сторонний (не текущий) origin.
function jevIsCrossOrigin(url) {
  if (!url) return false;
  const origin = jevGetOrigin(url);
  return origin !== '' && origin !== window.location.origin;
}

// Хост ссылки для отчёта.
function jevGetHost(url) {
  try {
    return new URL(url, window.location.href).hostname;
  } catch (e) {
    return '';
  }
}

// Текущая страница открыта по HTTPS.
function jevIsPageSecure() {
  return window.location.protocol === 'https:';
}

// Короткое текстовое описание элемента для отчёта.
function jevDescribeElement(el) {
  const parts = [el.tagName.toLowerCase()];
  if (el.id) parts.push(`#${el.id}`);
  if (el.name) parts.push(`[name="${el.name}"]`);
  if (el.type) parts.push(`[type="${el.type}"]`);
  const text = (el.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 60);
  if (!el.id && !el.name && text) parts.push(`«${text}»`);
  return parts.join(' ');
}

// Экранирование текста перед вставкой через innerHTML.
function jevEscapeHtml(value) {
  return String(value === null || value === undefined ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Функция для безопасного извлечения атрибутов элементов
function extractFormDetails() {
  const forms = document.querySelectorAll('form');
  return Array.from(forms).map(form => {
    const inputs = Array.from(form.querySelectorAll('input')).map(input => ({
      type: input.type || 'text',
      name: input.name || '',
      id: input.id || '',
      placeholder: input.placeholder || '',
      autocomplete: input.getAttribute('autocomplete') || '',
      isHidden: input.type === 'hidden'
    }));

    const action = form.getAttribute('action') || '';
    return {
      action,
      method: (form.getAttribute('method') || 'GET').toUpperCase(),
      isSecure: jevIsPageSecure(),
      actionIsCrossOrigin: action ? jevIsCrossOrigin(action) : false,
      actionIsInsecure: action ? jevGetOrigin(action).startsWith('http:') : false,
      hasPassword: inputs.some(input => input.type === 'password'),
      inputs
    };
  });
}

function extractScripts() {
  const scripts = Array.from(document.querySelectorAll('script'));
  return scripts.map(script => {
    const src = script.getAttribute('src') || '';
    return {
      src,
      isInline: !src,
      isCrossOrigin: src ? jevIsCrossOrigin(src) : false,
      hasIntegrity: script.hasAttribute('integrity'),
      async: script.async,
      defer: script.defer
    };
  });
}

// Ссылки: агрегируем опасные схемы и внешние переходы.
function extractLinks() {
  const links = Array.from(document.querySelectorAll('a[href]'));
  return links.map(link => {
    const href = (link.getAttribute('href') || '').trim();
    const lower = href.toLowerCase();
    return {
      href,
      target: link.getAttribute('target') || '',
      rel: link.getAttribute('rel') || '',
      isCrossOrigin: jevIsCrossOrigin(href),
      isJavascript: lower.startsWith('javascript:'),
      isData: lower.startsWith('data:')
    };
  });
}

// Ресурсы на HTTP, загруженные внутри HTTPS-страницы (mixed content).
function extractMixedContent() {
  if (!jevIsPageSecure()) return [];
  const selector = 'script[src], link[href], img[src], iframe[src], audio[src], video[src], source[src]';
  return Array.from(document.querySelectorAll(selector))
    .map(el => el.getAttribute('src') || el.getAttribute('href') || '')
    .filter(url => url.toLowerCase().startsWith('http:'));
}

// Автоматический редирект через meta refresh.
function extractMetaRefresh() {
  const meta = document.querySelector('meta[http-equiv="refresh" i]');
  return meta ? (meta.getAttribute('content') || '') : '';
}

function extractIframes() {
  const iframes = document.querySelectorAll('iframe');
  return Array.from(iframes).map(iframe => {
    const src = iframe.getAttribute('src') || '';
    return {
      src,
      sandbox: iframe.getAttribute('sandbox') || 'not-set',
      allow: iframe.getAttribute('allow') || '',
      isCrossOrigin: src ? jevIsCrossOrigin(src) : false,
      isHidden: iframe.offsetWidth === 0 && iframe.offsetHeight === 0
    };
  });
}

// Главная функция сбора данных для отправки в Jev AI
function collectPageSecurityData() {
  const links = extractLinks();
  return {
    url: window.location.href,
    title: document.title,
    protocol: window.location.protocol,
    forms: extractFormDetails(),
    scripts: extractScripts().slice(0, 50),
    iframes: extractIframes(),
    linksSummary: {
      total: links.length,
      crossOrigin: links.filter(link => link.isCrossOrigin).length,
      javascript: links.filter(link => link.isJavascript).length,
      data: links.filter(link => link.isData).length,
      blankWithoutNoopener: links.filter(
        link => link.target === '_blank' && !/noopener|noreferrer/i.test(link.rel)
      ).length
    },
    mixedContent: extractMixedContent().slice(0, 30),
    metaRefresh: extractMetaRefresh()
  };
}

// --------------------------------------------------------------------------
// Локальная эвристика потенциально опасных элементов
// --------------------------------------------------------------------------

// Находит элементы, которые могут представлять угрозу, и запоминает
// соответствие "id находки -> DOM-элемент" для последующей подсветки.
function detectDangerousElements() {
  jevFindingElements.clear();
  const findings = [];
  const pageSecure = jevIsPageSecure();

  const register = (el, category, severity, reason, detail) => {
    if (!el) return;
    const id = `jev-${++jevFindingSeq}`;
    jevFindingElements.set(id, el);
    findings.push({
      id,
      category,
      severity,
      reason,
      detail: detail || '',
      selector: jevDescribeElement(el)
    });
  };

  // 1. Формы: сбор паролей и отправка данных.
  document.querySelectorAll('form').forEach(form => {
    const passwordInput = form.querySelector('input[type="password"]');
    const action = form.getAttribute('action') || '';

    if (passwordInput && !pageSecure) {
      register(form, 'insecure_credentials', 'critical',
        'Форма собирает пароль на незащищённом соединении (HTTP)', action);
    } else if (passwordInput && action && jevIsCrossOrigin(action)) {
      register(form, 'credentials_exfiltration', 'high',
        'Форма с паролем отправляет данные на сторонний домен', jevGetOrigin(action));
    } else if (action.toLowerCase().startsWith('http:')) {
      register(form, 'insecure_action', 'high',
        'Форма отправляет данные по незащищённому HTTP', action);
    }
  });

  // 2. Сторонние скрипты без Subresource Integrity.
  let thirdPartyScripts = 0;
  document.querySelectorAll('script[src]').forEach(script => {
    const src = script.getAttribute('src') || '';
    // HTTP-скрипты на HTTPS-странице обрабатываются ниже (mixed content).
    if (pageSecure && src.toLowerCase().startsWith('http:')) return;
    if (jevIsCrossOrigin(src) && !script.hasAttribute('integrity') && thirdPartyScripts < 10) {
      thirdPartyScripts += 1;
      register(script, 'third_party_script', 'low',
        'Сторонний скрипт без Subresource Integrity (SRI)', jevGetHost(src));
    }
  });

  // 3. Фреймы: sandbox и кликджекинг.
  document.querySelectorAll('iframe').forEach(iframe => {
    const src = iframe.getAttribute('src') || '';
    if (!src) return;
    if (!iframe.hasAttribute('sandbox')) {
      register(iframe, 'clickjacking_risk', 'high',
        jevIsCrossOrigin(src) ? 'Сторонний iframe без атрибута sandbox'
                              : 'iframe без атрибута sandbox', src);
    } else if (jevIsCrossOrigin(src)) {
      register(iframe, 'third_party_frame', 'medium',
        'Сторонний iframe: ' + jevGetHost(src), src);
    }
  });

  // 4. Опасные ссылки (javascript:, data:, reverse tabnabbing).
  let unsafeLinks = 0;
  document.querySelectorAll('a[href]').forEach(link => {
    const href = (link.getAttribute('href') || '').trim();
    const lower = href.toLowerCase();
    if (unsafeLinks >= 10) return;
    if (lower.startsWith('javascript:')) {
      unsafeLinks += 1;
      register(link, 'javascript_link', 'high',
        'Ссылка с протоколом javascript:', href.slice(0, 80));
    } else if (lower.startsWith('data:')) {
      unsafeLinks += 1;
      register(link, 'data_link', 'medium',
        'Ссылка с протоколом data: (возможна подмена контента)', href.slice(0, 80));
    } else if (link.getAttribute('target') === '_blank' &&
               !/noopener|noreferrer/i.test(link.getAttribute('rel') || '')) {
      unsafeLinks += 1;
      register(link, 'reverse_tabnabbing', 'medium',
        'target="_blank" без rel="noopener"', href);
    }
  });

  // 5. Смешанный контент на HTTPS-странице.
  if (pageSecure) {
    document.querySelectorAll('script[src], link[href], img[src], iframe[src]').forEach(el => {
      const url = el.getAttribute('src') || el.getAttribute('href') || '';
      if (url.toLowerCase().startsWith('http:')) {
        register(el, 'mixed_content', 'high',
          'Незащищённый ресурс (HTTP) на HTTPS-странице', url);
      }
    });
  }

  // 6. Автоматический редирект через meta refresh.
  const refresh = extractMetaRefresh();
  if (refresh && /url\s*=/i.test(refresh)) {
    register(document.querySelector('meta[http-equiv="refresh" i]'), 'meta_redirect', 'medium',
      'Автоматический редирект через meta refresh', refresh);
  }

  // Сортируем по важности и отсекаем лишнее.
  findings.sort((a, b) => JEV_SEVERITY_ORDER[b.severity] - JEV_SEVERITY_ORDER[a.severity]);
  if (findings.length > JEV_MAX_FINDINGS) findings.length = JEV_MAX_FINDINGS;

  const keptIds = new Set(findings.map(finding => finding.id));
  for (const id of Array.from(jevFindingElements.keys())) {
    if (!keptIds.has(id)) jevFindingElements.delete(id);
  }

  return findings;
}

// --------------------------------------------------------------------------
// Сканирование по контекстному меню: собираем данные, подсвечиваем находки и
// запрашиваем у Jev AI оценку через background, показывая мини-панель на странице.
// --------------------------------------------------------------------------

async function runInPageScan() {
  try {
    const pageData = collectPageSecurityData();
    jevLastPageSummary = pageData;
    const findings = detectDangerousElements();
    pageData.findings = findings;
    // Сразу подсвечиваем локально найденные опасные элементы.
    highlightFindings(findings);

    // Запрос к Jev AI выполняет service worker (читает API-ключ из хранилища).
    const response = await chrome.runtime.sendMessage({ action: "analyze_page", pageData });
    if (!response || !response.success) {
      renderInPageAiSummary(null, (response && response.error) || "Неизвестная ошибка Jev AI");
      return;
    }
    renderInPageAiSummary(response.result, null);
  } catch (error) {
    renderInPageAiSummary(null, error.message);
  }
}

// --------------------------------------------------------------------------
// Автоматическое удаление опасных элементов при загрузке страницы.
// Включается настройкой jevAutoRemoveDangerous в chrome.storage.local (по
// умолчанию выключено). Локальная эвристика работает без обращения к Jev AI.
// --------------------------------------------------------------------------

let jevAutoRemoveEnabled = false;
let jevAutoRemoveObserver = null;
let jevAutoRemoveTimer = null;

// Полное сканирование DOM и удаление всех найденных опасных элементов.
function jevAutoRemoveDangerous() {
  const findings = detectDangerousElements();
  if (!findings.length) return;
  removeAllFindings();
}

// Реагируем только на появление новых узлов, игнорируя собственный UI
// расширения (панели находок и оценки Jev AI), чтобы не зациклиться.
function jevAutoMutationsRelevant(mutations) {
  for (const mutation of mutations) {
    for (const node of mutation.addedNodes) {
      if (!(node instanceof Element)) continue;
      if (node.id && node.id.startsWith('jev-')) continue;
      if (node.closest && node.closest('#jev-danger-panel, #jev-ai-panel')) continue;
      return true;
    }
  }
  return false;
}

// Отложенный запуск, чтобы серия вставок не вызывала многократное сканирование.
function jevScheduleAutoRemove() {
  if (!jevAutoRemoveEnabled) return;
  clearTimeout(jevAutoRemoveTimer);
  jevAutoRemoveTimer = setTimeout(() => {
    if (jevAutoRemoveEnabled) jevAutoRemoveDangerous();
  }, 200);
}

function jevStartAutoRemove() {
  if (jevAutoRemoveObserver) return;
  const root = document.documentElement || document;
  jevAutoRemoveObserver = new MutationObserver((mutations) => {
    if (jevAutoMutationsRelevant(mutations)) jevScheduleAutoRemove();
  });
  jevAutoRemoveObserver.observe(root, { childList: true, subtree: true });
  // Первичное сканирование, когда DOM уже построен.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', jevAutoRemoveDangerous, { once: true });
  } else {
    jevScheduleAutoRemove();
  }
}

function jevStopAutoRemove() {
  if (jevAutoRemoveObserver) {
    jevAutoRemoveObserver.disconnect();
    jevAutoRemoveObserver = null;
  }
  clearTimeout(jevAutoRemoveTimer);
}

function jevApplyAutoRemove(enabled) {
  jevAutoRemoveEnabled = enabled;
  if (enabled) jevStartAutoRemove();
  else jevStopAutoRemove();
}

// Читаем настройку при инициализации и следим за её изменением из popup.
chrome.storage.local.get(['jevAutoRemoveDangerous'], (stored) => {
  jevApplyAutoRemove(!!stored.jevAutoRemoveDangerous);
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.jevAutoRemoveDangerous) {
    jevApplyAutoRemove(!!changes.jevAutoRemoveDangerous.newValue);
  }
});

// Достаёт вероятность из ответа Jev AI в процентах.
function jevMetricPercent(answer, field) {
  if (!answer) return 0;
  const raw = typeof answer[field] === 'number' ? answer[field]
    : (typeof answer.probability === 'number' ? answer.probability : 0);
  return Math.round(raw * 100);
}

const JEV_CATEGORY_LABELS = {
  "safe": "Безопасно",
  "insecure_form": "Незащищенная форма (HTTP)",
  "suspicious_scripts": "Подозрительные скрипты",
  "clickjacking_risk": "Риск Clickjacking (iframe)",
  "mixed_content": "Смешанный контент (HTTP/HTTPS)",
  "credential_harvest": "Обманный сбор учётных данных",
  "data_exfiltration": "Утечка данных на сторонние домены",
  "deceptive_ui": "Вводящий в заблуждение интерфейс"
};

// Цветовой статус риска по проценту (как в popup).
function jevMetricClass(percent) {
  if (percent < 30) return 'jev-ai-safe';
  if (percent < 70) return 'jev-ai-warn';
  return 'jev-ai-danger';
}

// Мини-панель с оценкой безопасности страницы от Jev AI (левый нижний угол).
function renderInPageAiSummary(aiResult, errorMessage) {
  const existing = document.getElementById('jev-ai-panel');
  if (existing) existing.remove();

  const panel = document.createElement('div');
  panel.id = 'jev-ai-panel';
  panel.className = 'jev-ai-panel';

  const header = document.createElement('div');
  header.className = 'jev-ai-panel-header';

  const title = document.createElement('span');
  title.textContent = '🛡️ Jev AI: безопасность страницы';

  const close = document.createElement('button');
  close.className = 'jev-btn-close';
  close.type = 'button';
  close.textContent = '✕';
  close.addEventListener('click', () => panel.remove());

  header.appendChild(title);
  header.appendChild(close);
  panel.appendChild(header);

  const body = document.createElement('div');
  body.className = 'jev-ai-panel-body';

  if (errorMessage) {
    const err = document.createElement('div');
    err.className = 'jev-ai-error';
    err.textContent = errorMessage;
    body.appendChild(err);
  } else {
    const phishing = jevMetricPercent(aiResult.phishing_prob, 'noul');
    const harvest = jevMetricPercent(aiResult.credential_harvest, 'noul');
    const categoryKey = aiResult.risk_category && aiResult.risk_category.choice
      ? aiResult.risk_category.choice
      : 'safe';
    const rawScore = aiResult.severity_score && typeof aiResult.severity_score.score === 'number'
      ? aiResult.severity_score.score
      : 0;
    const score = Math.min(5, Math.max(1, Math.round(rawScore + 1)));

    const addRow = (label, value, cls) => {
      const line = document.createElement('div');
      line.className = 'jev-ai-metric';
      const name = document.createElement('span');
      name.textContent = label;
      const val = document.createElement('strong');
      val.textContent = value;
      if (cls) val.className = cls;
      line.appendChild(name);
      line.appendChild(val);
      body.appendChild(line);
    };

    addRow('Угроза фишинга', `${phishing}%`, jevMetricClass(phishing));
    addRow('Сбор учётных данных', `${harvest}%`, jevMetricClass(harvest));
    addRow('Основной вектор', JEV_CATEGORY_LABELS[categoryKey] || categoryKey,
      categoryKey === 'safe' ? 'jev-ai-safe' : 'jev-ai-danger');
    addRow('Индекс опасности', `${score} / 5`,
      score >= 4 ? 'jev-ai-danger' : (score >= 3 ? 'jev-ai-warn' : 'jev-ai-safe'));
  }

  panel.appendChild(body);

  const footer = document.createElement('div');
  footer.className = 'jev-ai-panel-footer';
  const clearBtn = document.createElement('button');
  clearBtn.className = 'jev-btn-link';
  clearBtn.type = 'button';
  clearBtn.textContent = 'Снять подсветку';
  clearBtn.addEventListener('click', () => {
    clearHighlights();
    panel.remove();
  });
  footer.appendChild(clearBtn);
  panel.appendChild(footer);

  document.body.appendChild(panel);
}

// Слушатель сообщений от popup.js или background.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "scan_page") {
    try {
      // 1. Собираем структуру страницы.
      const pageData = collectPageSecurityData();
      jevLastPageSummary = pageData;
      // 2. Локально находим потенциально опасные элементы.
      const findings = detectDangerousElements();
      pageData.findings = findings;
      // 3. Сразу подсвечиваем их прямо на странице.
      highlightFindings(findings);
      
      // Отправляем структурированные данные обратно в фоновый скрипт
      sendResponse({ success: true, data: pageData });
    } catch (error) {
      sendResponse({ success: false, error: error.message });
    }
  } else if (message.action === "scan_page_from_menu") {
    runInPageScan();
    sendResponse({ success: true });
  } else if (message.action === "clear_highlights") {
    clearHighlights();
    sendResponse({ success: true });
  } else if (message.action === "focus_finding") {
    focusFinding(message.id);
    sendResponse({ success: true });
  } else if (message.action === "remove_finding") {
    sendResponse({ success: removeFinding(message.id) });
  } else if (message.action === "remove_all_findings") {
    sendResponse({ success: true, removed: removeAllFindings() });
  }
  return true; // Держим канал связи открытым для асинхронного ответа
});

// --------------------------------------------------------------------------
// Визуализация опасных элементов на странице
// --------------------------------------------------------------------------

// Заменяет title элемента, сохраняя оригинальное значение.
function jevSetFindingTitle(el, text) {
  if (!jevOriginalTitles.has(el)) {
    jevOriginalTitles.set(el, el.hasAttribute('title') ? el.getAttribute('title') : null);
  }
  el.setAttribute('title', text);
}

// Снимает подсветку и панель, восстанавливает оригинальные title.
function clearHighlights() {
  document.querySelectorAll('.jev-danger-highlight').forEach(el => {
    if (jevOriginalTitles.has(el)) {
      const original = jevOriginalTitles.get(el);
      if (original === null) el.removeAttribute('title');
      else el.setAttribute('title', original);
      jevOriginalTitles.delete(el);
    }
    el.classList.remove('jev-danger-highlight', 'jev-sev-critical', 'jev-sev-high',
      'jev-sev-medium', 'jev-sev-low', 'jev-danger-flash');
  });
  const panel = document.getElementById('jev-danger-panel');
  if (panel) panel.remove();
  jevCurrentFindings = [];
}

// Прокручивает страницу к элементу и подсвечивает его вспышкой.
function focusFinding(id) {
  const el = jevFindingElements.get(id);
  if (!el || !el.isConnected) return;
  el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  el.classList.add('jev-danger-flash');
  setTimeout(() => el.classList.remove('jev-danger-flash'), 1600);
}

// Удаляет DOM-элемент находки со страницы. Возвращает true, если что-то удалено.
function removeFinding(id) {
  const el = jevFindingElements.get(id);
  if (!el || !el.isConnected) {
    jevFindingElements.delete(id);
    refreshDangerPanel();
    return false;
  }
  el.remove();
  jevFindingElements.delete(id);
  refreshDangerPanel();
  return true;
}

// Удаляет все найденные опасные элементы. Возвращает число удалённых.
function removeAllFindings() {
  let removed = 0;
  for (const [id, el] of Array.from(jevFindingElements)) {
    if (el.isConnected) {
      el.remove();
      removed += 1;
    }
    jevFindingElements.delete(id);
  }
  if (removed > 0) refreshDangerPanel();
  return removed;
}

// Перерисовывает панель по актуальному списку (отбрасывает отвалившиеся элементы).
function refreshDangerPanel() {
  jevCurrentFindings = jevCurrentFindings.filter(finding => {
    const el = jevFindingElements.get(finding.id);
    return el && el.isConnected;
  });
  renderDangerPanel(jevCurrentFindings);
}

// Строки сводки по структуре страницы (пары label -> value).
function jevBuildSummaryRows(data) {
  const links = (data && data.linksSummary) || {};
  return [
    ['Формы', (data.forms || []).length],
    ['Скрипты', (data.scripts || []).length],
    ['iframe', (data.iframes || []).length],
    ['Внешние ссылки', `${links.crossOrigin || 0} / ${links.total || 0}`],
    ['javascript:/data: ссылки', (links.javascript || 0) + (links.data || 0)],
    ['Смешанный контент', (data.mixedContent || []).length]
  ];
}

// Панель со сводкой по структуре и списком найденных опасных элементов
// (правый нижний угол страницы).
function renderDangerPanel(findings) {
  const existing = document.getElementById('jev-danger-panel');
  if (existing) existing.remove();
  if (!findings.length && !jevLastPageSummary) return;

  const panel = document.createElement('div');
  panel.id = 'jev-danger-panel';
  panel.className = 'jev-danger-panel';

  const header = document.createElement('div');
  header.className = 'jev-danger-panel-header';

  const title = document.createElement('span');
  title.textContent = findings.length
    ? `⚠️ Потенциально опасные элементы: ${findings.length}`
    : 'ℹ️ Опасных элементов не обнаружено';

  const close = document.createElement('button');
  close.className = 'jev-btn-close';
  close.type = 'button';
  close.textContent = '✕';
  close.addEventListener('click', clearHighlights);

  const removeAll = document.createElement('button');
  removeAll.className = 'jev-btn-link';
  removeAll.type = 'button';
  removeAll.textContent = 'Удалить все';
  removeAll.addEventListener('click', removeAllFindings);

  header.appendChild(title);
  if (findings.length) header.appendChild(removeAll);
  header.appendChild(close);
  panel.appendChild(header);

  // Сводка по структуре страницы (формы, скрипты, фреймы, ссылки).
  if (jevLastPageSummary) {
    const summary = document.createElement('div');
    summary.className = 'jev-danger-panel-summary';
    summary.innerHTML = jevBuildSummaryRows(jevLastPageSummary)
      .map(([label, value]) =>
        `<div class="jev-summary-row"><span>${jevEscapeHtml(label)}</span>` +
        `<strong>${jevEscapeHtml(String(value))}</strong></div>`)
      .join('');
    panel.appendChild(summary);
  }

  const list = document.createElement('div');
  list.className = 'jev-danger-panel-list';

  if (!findings.length) {
    const empty = document.createElement('div');
    empty.className = 'jev-danger-empty';
    empty.textContent = 'Опасных элементов не обнаружено';
    list.appendChild(empty);
  }

  findings.forEach(finding => {
    const item = document.createElement('div');
    item.className = `jev-danger-item jev-sev-${finding.severity}`;
    item.innerHTML =
      `<div class="jev-danger-item-title">${jevEscapeHtml(finding.reason)}</div>` +
      `<div class="jev-danger-item-detail">${jevEscapeHtml(finding.selector)}` +
      (finding.detail ? ` — ${jevEscapeHtml(finding.detail)}` : '') +
      '</div>';

    const removeBtn = document.createElement('button');
    removeBtn.className = 'jev-btn-remove';
    removeBtn.type = 'button';
    removeBtn.textContent = 'Удалить';
    removeBtn.title = 'Удалить элемент со страницы';
    removeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      removeFinding(finding.id);
    });
    item.appendChild(removeBtn);

    item.addEventListener('click', () => focusFinding(finding.id));
    list.appendChild(item);
  });

  panel.appendChild(list);
  document.body.appendChild(panel);
}

// Подсвечивает найденные элементы и строит панель-отчёт.
function highlightFindings(findings) {
  clearHighlights();
  jevCurrentFindings = findings;
  findings.forEach(finding => {
    const el = jevFindingElements.get(finding.id);
    if (!el || !el.isConnected) return;
    el.classList.add('jev-danger-highlight', `jev-sev-${finding.severity}`);
    jevSetFindingTitle(el, 'Jev AI: ' + finding.reason +
      (finding.detail ? ' — ' + finding.detail : ''));
  });
  renderDangerPanel(findings);
}
