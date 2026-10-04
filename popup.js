// ---------------------------------------------------------------------------
// Settings: the TypeSafe Jev API key is stored in chrome.storage.local
// ---------------------------------------------------------------------------
const apiKeyInput = document.getElementById('apiKey');
const saveBtn = document.getElementById('saveBtn');
const saveStatus = document.getElementById('saveStatus');

chrome.storage.local.get(['jevApiKey'], (result) => {
  if (result.jevApiKey) apiKeyInput.value = result.jevApiKey;
});

let saveStatusTimer = null;
let saveBtnTimer = null;

function showSaveStatus(text, ok) {
  saveStatus.textContent = text;
  saveStatus.className = 'save-status ' + (ok ? 'ok' : 'error');
  clearTimeout(saveStatusTimer);
  saveStatusTimer = setTimeout(() => {
    saveStatus.textContent = '';
    saveStatus.className = 'save-status';
  }, 2600);
}

saveBtn.addEventListener('click', () => {
  const key = apiKeyInput.value.trim();
  chrome.storage.local.set({ jevApiKey: key }, () => {
    saveBtn.classList.add('saved');
    saveBtn.textContent = 'Saved ✓';
    clearTimeout(saveBtnTimer);
    saveBtnTimer = setTimeout(() => {
      saveBtn.classList.remove('saved');
      saveBtn.textContent = 'Save settings';
    }, 1600);
    showSaveStatus(key ? 'API key saved' : 'API key cleared', true);
  });
});

// ---------------------------------------------------------------------------
// Auto-removal of dangerous elements on page load (off by default).
// The setting is read by content.js and applied without reloading the page.
// ---------------------------------------------------------------------------
const autoRemoveInput = document.getElementById('autoRemove');

chrome.storage.local.get(['jevAutoRemoveDangerous'], (result) => {
  autoRemoveInput.checked = !!result.jevAutoRemoveDangerous;
});

autoRemoveInput.addEventListener('change', () => {
  chrome.storage.local.set({ jevAutoRemoveDangerous: autoRemoveInput.checked }, () => {
    showSaveStatus(autoRemoveInput.checked ? 'Auto-removal enabled' : 'Auto-removal disabled', true);
  });
});

