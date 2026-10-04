// ==========================================================================
// Jev Page Safety — content script
// Collects the page structure, locally detects potentially dangerous
// elements and highlights them right on the page.
// ==========================================================================

// finding id -> live DOM element (for highlighting and scrolling to it).
const jevFindingElements = new Map();
// Original title attribute values, so they can be restored later.
const jevOriginalTitles = new WeakMap();
// Monotonic counter of finding ids.
let jevFindingSeq = 0;

// Severity order used to sort findings.
const JEV_SEVERITY_ORDER = { critical: 3, high: 2, medium: 1, low: 0 };
// Maximum number of findings shown on the page and in the popup.
const JEV_MAX_FINDINGS = 40;
// Findings currently shown (keeps the panel in sync after a removal).
let jevCurrentFindings = [];
// Structure summary of the last scanned page (for the on-page panel).
let jevLastPageSummary = null;

// --------------------------------------------------------------------------
// Helper functions
// --------------------------------------------------------------------------

// Origin of a link (relative paths resolved) or '' when parsing fails.
function jevGetOrigin(url) {
  try {
    return new URL(url, window.location.href).origin;
  } catch (e) {
    return '';
  }
}

// Whether the link points to a third-party (non-current) origin.
function jevIsCrossOrigin(url) {
  if (!url) return false;
  const origin = jevGetOrigin(url);
  return origin !== '' && origin !== window.location.origin;
}

// Host name of a link for the report.
function jevGetHost(url) {
  try {
    return new URL(url, window.location.href).hostname;
  } catch (e) {
    return '';
  }
}

// Whether the current page is served over HTTPS.
function jevIsPageSecure() {
  return window.location.protocol === 'https:';
}

// Short text description of an element for the report.
function jevDescribeElement(el) {
  const parts = [el.tagName.toLowerCase()];
  if (el.id) parts.push(`#${el.id}`);
  if (el.name) parts.push(`[name="${el.name}"]`);
  if (el.type) parts.push(`[type="${el.type}"]`);
  const text = (el.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 60);
  if (!el.id && !el.name && text) parts.push(`«${text}»`);
  return parts.join(' ');
}

// Escapes text before inserting it through innerHTML.
function jevEscapeHtml(value) {
  return String(value === null || value === undefined ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Safely extracts attributes of form fields.
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

// Links: aggregate dangerous schemes and outbound navigation.
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

// HTTP resources loaded inside an HTTPS page (mixed content).
function extractMixedContent() {
  if (!jevIsPageSecure()) return [];
  const selector = 'script[src], link[href], img[src], iframe[src], audio[src], video[src], source[src]';
  return Array.from(document.querySelectorAll(selector))
    .map(el => el.getAttribute('src') || el.getAttribute('href') || '')
    .filter(url => url.toLowerCase().startsWith('http:'));
}

// Automatic redirect through meta refresh.
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

// Main data collection function that produces the payload sent to Jev AI.
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
// Local heuristic detection of potentially dangerous elements
// --------------------------------------------------------------------------

// Finds elements that may pose a threat and records the
// "finding id -> DOM element" mapping for later highlighting.
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

  // 1. Forms: password harvesting and data submission.
  document.querySelectorAll('form').forEach(form => {
    const passwordInput = form.querySelector('input[type="password"]');
    const action = form.getAttribute('action') || '';

    if (passwordInput && !pageSecure) {
      register(form, 'insecure_credentials', 'critical',
        'Password form over an unencrypted connection (HTTP)', action);
    } else if (passwordInput && action && jevIsCrossOrigin(action)) {
      register(form, 'credentials_exfiltration', 'high',
        'Password form submits data to a third-party domain', jevGetOrigin(action));
    } else if (action.toLowerCase().startsWith('http:')) {
      register(form, 'insecure_action', 'high',
        'Form submits data over unencrypted HTTP', action);
    }
  });

  // 2. Third-party scripts without Subresource Integrity.
  let thirdPartyScripts = 0;
  document.querySelectorAll('script[src]').forEach(script => {
    const src = script.getAttribute('src') || '';
    // HTTP scripts on an HTTPS page are handled below (mixed content).
    if (pageSecure && src.toLowerCase().startsWith('http:')) return;
    if (jevIsCrossOrigin(src) && !script.hasAttribute('integrity') && thirdPartyScripts < 10) {
      thirdPartyScripts += 1;
      register(script, 'third_party_script', 'low',
        'Third-party script without Subresource Integrity (SRI)', jevGetHost(src));
    }
  });

  // 3. Frames: sandbox and clickjacking.
  document.querySelectorAll('iframe').forEach(iframe => {
    const src = iframe.getAttribute('src') || '';
    if (!src) return;
    if (!iframe.hasAttribute('sandbox')) {
      register(iframe, 'clickjacking_risk', 'high',
        jevIsCrossOrigin(src) ? 'Third-party iframe without a sandbox attribute'
                              : 'iframe without a sandbox attribute', src);
    } else if (jevIsCrossOrigin(src)) {
      register(iframe, 'third_party_frame', 'medium',
        'Third-party iframe: ' + jevGetHost(src), src);
    }
  });

  // 4. Dangerous links (javascript:, data:, reverse tabnabbing).
  let unsafeLinks = 0;
  document.querySelectorAll('a[href]').forEach(link => {
    const href = (link.getAttribute('href') || '').trim();
    const lower = href.toLowerCase();
    if (unsafeLinks >= 10) return;
    if (lower.startsWith('javascript:')) {
      unsafeLinks += 1;
      register(link, 'javascript_link', 'high',
        'Link with the javascript: scheme', href.slice(0, 80));
    } else if (lower.startsWith('data:')) {
      unsafeLinks += 1;
      register(link, 'data_link', 'medium',
        'Link with the data: scheme (content substitution possible)', href.slice(0, 80));
    } else if (link.getAttribute('target') === '_blank' &&
               !/noopener|noreferrer/i.test(link.getAttribute('rel') || '')) {
      unsafeLinks += 1;
      register(link, 'reverse_tabnabbing', 'medium',
        'target="_blank" without rel="noopener"', href);
    }
  });

  // 5. Mixed content on an HTTPS page.
  if (pageSecure) {
    document.querySelectorAll('script[src], link[href], img[src], iframe[src]').forEach(el => {
      const url = el.getAttribute('src') || el.getAttribute('href') || '';
      if (url.toLowerCase().startsWith('http:')) {
        register(el, 'mixed_content', 'high',
          'Unencrypted resource (HTTP) on an HTTPS page', url);
      }
    });
  }

  // 6. Automatic redirect through meta refresh.
  const refresh = extractMetaRefresh();
  if (refresh && /url\s*=/i.test(refresh)) {
    register(document.querySelector('meta[http-equiv="refresh" i]'), 'meta_redirect', 'medium',
      'Automatic redirect through meta refresh', refresh);
  }

  // Sort by severity and drop the rest.
  findings.sort((a, b) => JEV_SEVERITY_ORDER[b.severity] - JEV_SEVERITY_ORDER[a.severity]);
  if (findings.length > JEV_MAX_FINDINGS) findings.length = JEV_MAX_FINDINGS;

  const keptIds = new Set(findings.map(finding => finding.id));
  for (const id of Array.from(jevFindingElements.keys())) {
    if (!keptIds.has(id)) jevFindingElements.delete(id);
  }

  return findings;
}

// --------------------------------------------------------------------------
// Context-menu scan: collect data, highlight findings and ask
// Jev AI for an assessment through the background, showing a mini-panel on the page.
// --------------------------------------------------------------------------

async function runInPageScan() {
  try {
    const pageData = collectPageSecurityData();
    jevLastPageSummary = pageData;
    const findings = detectDangerousElements();
    pageData.findings = findings;
    // Immediately highlight the dangerous elements found locally.
    highlightFindings(findings);

    // The Jev AI request is made by the service worker (it reads the API key from storage).
    const response = await chrome.runtime.sendMessage({ action: "analyze_page", pageData });
    if (!response || !response.success) {
      renderInPageAiSummary(null, (response && response.error) || "Unknown Jev AI error");
      return;
    }
    renderInPageAiSummary(response.result, null);
  } catch (error) {
    renderInPageAiSummary(null, error.message);
  }
}

// --------------------------------------------------------------------------
// Automatic removal of dangerous elements on page load.
// Enabled by the jevAutoRemoveDangerous setting in chrome.storage.local
// (off by default). The local heuristic runs without calling Jev AI.
// --------------------------------------------------------------------------

let jevAutoRemoveEnabled = false;
let jevAutoRemoveObserver = null;
let jevAutoRemoveTimer = null;

// Full DOM scan removing every dangerous element found.
function jevAutoRemoveDangerous() {
  const findings = detectDangerousElements();
  if (!findings.length) return;
  removeAllFindings();
}

// React only to new nodes, ignoring the extension's own UI
// (findings and Jev AI panels), so we do not loop forever.
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

// Debounced trigger, so a burst of insertions does not cause repeated scans.
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
  // Initial scan once the DOM is already built.
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

// Read the setting at init and watch for changes coming from the popup.
chrome.storage.local.get(['jevAutoRemoveDangerous'], (stored) => {
  jevApplyAutoRemove(!!stored.jevAutoRemoveDangerous);
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.jevAutoRemoveDangerous) {
    jevApplyAutoRemove(!!changes.jevAutoRemoveDangerous.newValue);
  }
});

// Extracts a probability from the Jev AI response as a percentage.
function jevMetricPercent(answer, field) {
  if (!answer) return 0;
  const raw = typeof answer[field] === 'number' ? answer[field]
    : (typeof answer.probability === 'number' ? answer.probability : 0);
  return Math.round(raw * 100);
}

const JEV_CATEGORY_LABELS = {
  "safe": "Safe",
  "insecure_form": "Insecure form (HTTP)",
  "suspicious_scripts": "Suspicious scripts",
  "clickjacking_risk": "Clickjacking risk (iframe)",
  "mixed_content": "Mixed content (HTTP/HTTPS)",
  "credential_harvest": "Deceptive credential harvesting",
  "data_exfiltration": "Data exfiltration to third-party domains",
  "deceptive_ui": "Deceptive UI"
};

// Risk color status by percentage (same as in the popup).
function jevMetricClass(percent) {
  if (percent < 30) return 'jev-ai-safe';
  if (percent < 70) return 'jev-ai-warn';
  return 'jev-ai-danger';
}

// Mini-panel with the Jev AI page safety assessment (bottom-left corner).
function renderInPageAiSummary(aiResult, errorMessage) {
  const existing = document.getElementById('jev-ai-panel');
  if (existing) existing.remove();

  const panel = document.createElement('div');
  panel.id = 'jev-ai-panel';
  panel.className = 'jev-ai-panel';

  const header = document.createElement('div');
  header.className = 'jev-ai-panel-header';

  const title = document.createElement('span');
  title.textContent = '🛡️ Jev AI: page safety';

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

    addRow('Phishing threat', `${phishing}%`, jevMetricClass(phishing));
    addRow('Credential harvesting', `${harvest}%`, jevMetricClass(harvest));
    addRow('Main vector', JEV_CATEGORY_LABELS[categoryKey] || categoryKey,
      categoryKey === 'safe' ? 'jev-ai-safe' : 'jev-ai-danger');
    addRow('Risk index', `${score} / 5`,
      score >= 4 ? 'jev-ai-danger' : (score >= 3 ? 'jev-ai-warn' : 'jev-ai-safe'));
  }

  panel.appendChild(body);

  const footer = document.createElement('div');
  footer.className = 'jev-ai-panel-footer';
  const clearBtn = document.createElement('button');
  clearBtn.className = 'jev-btn-link';
  clearBtn.type = 'button';
  clearBtn.textContent = 'Clear highlights';
  clearBtn.addEventListener('click', () => {
    clearHighlights();
    panel.remove();
  });
  footer.appendChild(clearBtn);
  panel.appendChild(footer);

  document.body.appendChild(panel);
}

// Message listener from popup.js or background.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "scan_page") {
    try {
      // 1. Collect the page structure.
      const pageData = collectPageSecurityData();
      jevLastPageSummary = pageData;
      // 2. Locally find potentially dangerous elements.
      const findings = detectDangerousElements();
      pageData.findings = findings;
      // 3. Immediately highlight them right on the page.
      highlightFindings(findings);
      
      // Send the structured data back to the background script.
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
  return true; // Keep the channel open for the asynchronous response
});

// --------------------------------------------------------------------------
// Visualization of dangerous elements on the page
// --------------------------------------------------------------------------

// Replaces the element's title, remembering the original value.
function jevSetFindingTitle(el, text) {
  if (!jevOriginalTitles.has(el)) {
    jevOriginalTitles.set(el, el.hasAttribute('title') ? el.getAttribute('title') : null);
  }
  el.setAttribute('title', text);
}

// Removes highlights and the panel, restores the original titles.
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

// Scrolls the page to the element and flashes it.
function focusFinding(id) {
  const el = jevFindingElements.get(id);
  if (!el || !el.isConnected) return;
  el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  el.classList.add('jev-danger-flash');
  setTimeout(() => el.classList.remove('jev-danger-flash'), 1600);
}

// Removes the finding's DOM element from the page. Returns true if something was removed.
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

// Removes all detected dangerous elements. Returns how many were removed.
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

// Re-renders the panel from the up-to-date list (drops detached elements).
function refreshDangerPanel() {
  jevCurrentFindings = jevCurrentFindings.filter(finding => {
    const el = jevFindingElements.get(finding.id);
    return el && el.isConnected;
  });
  renderDangerPanel(jevCurrentFindings);
}

// Summary rows of the page structure (label -> value pairs).
function jevBuildSummaryRows(data) {
  const links = (data && data.linksSummary) || {};
  return [
    ['Forms', (data.forms || []).length],
    ['Scripts', (data.scripts || []).length],
    ['iframe', (data.iframes || []).length],
    ['Cross-origin links', `${links.crossOrigin || 0} / ${links.total || 0}`],
    ['javascript:/data: links', (links.javascript || 0) + (links.data || 0)],
    ['Mixed content', (data.mixedContent || []).length]
  ];
}

// Panel with the page structure summary and the list of detected dangerous
// elements (bottom-right corner of the page).
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
    ? `⚠️ Potentially dangerous elements: ${findings.length}`
    : 'ℹ️ No dangerous elements detected';

  const close = document.createElement('button');
  close.className = 'jev-btn-close';
  close.type = 'button';
  close.textContent = '✕';
  close.addEventListener('click', clearHighlights);

  const removeAll = document.createElement('button');
  removeAll.className = 'jev-btn-link';
  removeAll.type = 'button';
  removeAll.textContent = 'Remove all';
  removeAll.addEventListener('click', removeAllFindings);

  header.appendChild(title);
  if (findings.length) header.appendChild(removeAll);
  header.appendChild(close);
  panel.appendChild(header);

  // Page structure summary (forms, scripts, frames, links).
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
    empty.textContent = 'No dangerous elements detected';
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
    removeBtn.textContent = 'Remove';
    removeBtn.title = 'Remove the element from the page';
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

// Highlights the detected elements and builds the report panel.
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
