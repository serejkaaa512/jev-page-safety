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

document.getElementById('scanBtn').addEventListener('click', async () => {
  const scanBtn = document.getElementById('scanBtn');
  const loader = document.getElementById('loader');
  const resultBox = document.getElementById('resultBox');

  scanBtn.disabled = true;
  loader.style.display = 'block';
  resultBox.style.display = 'none';

  // 1. Get the active browser tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  if (!tab) {
    alert("Could not find an active tab.");
    resetUI();
    return;
  }

  // 2. Send a message to content.js to collect the DOM structure
  chrome.tabs.sendMessage(tab.id, { action: "scan_page" }, (response) => {
    // lastError appears when the content script is unavailable (the page was not
    // reloaded after the extension was installed, or it is a browser page).
    if (chrome.runtime.lastError || !response || !response.success) {
      alert("Failed to scan the page. Reload the tab and try again.");
      resetUI();
      return;
    }

    // 3. Send the sanitized JSON to background.js for the Jev AI request
    chrome.runtime.sendMessage({ action: "analyze_page", pageData: response.data }, (apiResponse) => {
      resetUI();

      // If the service worker did not answer (the port closed), the callback arrives with lastError.
      if (chrome.runtime.lastError) {
        alert("Jev AI service is unavailable: " + chrome.runtime.lastError.message);
        return;
      }
      if (apiResponse && apiResponse.success) {
        renderResults(apiResponse.result);
      } else {
        alert("Jev AI request failed: " + (apiResponse?.error || "Unknown error"));
      }
    });
  });
});

function resetUI() {
  document.getElementById('scanBtn').disabled = false;
  document.getElementById('loader').style.display = 'none';
}

// 4. Parses the strictly typed Jev AI response and renders the metrics
function renderResults(jevOutput) {
  const resultBox = document.getElementById('resultBox');
  resultBox.style.display = 'block';

  // 1. Parse the Noul response (phishing threat)
  // In the response: jevOutput.phishing_prob.noul holds the value (e.g. 0.23)
  const phishingProb = (jevOutput.phishing_prob && typeof jevOutput.phishing_prob.noul === 'number') 
    ? jevOutput.phishing_prob.noul 
    : 0.0;
  
  const phishingPercentage = Math.round(phishingProb * 100);
  
  const pVal = document.getElementById('phishingVal');
  const pBar = document.getElementById('phishingBar');
  pVal.innerText = `${phishingPercentage}%`;
  pBar.style.width = `${phishingPercentage}%`;
  
  if (phishingPercentage < 30) {
    pVal.className = "metric-value risk-safe";
    pBar.style.backgroundColor = "#16a34a"; // green
  } else if (phishingPercentage < 70) {
    pVal.className = "metric-value risk-warning";
    pBar.style.backgroundColor = "#d97706"; // yellow
  } else {
    pVal.className = "metric-value risk-danger";
    pBar.style.backgroundColor = "#dc2626"; // red
  }

  // 1b. Parse the Noul response (deceptive credential harvesting)
  const harvestProb = (jevOutput.credential_harvest && typeof jevOutput.credential_harvest.noul === 'number')
    ? jevOutput.credential_harvest.noul
    : 0.0;

  const harvestPercentage = Math.round(harvestProb * 100);
  const hVal = document.getElementById('harvestVal');
  const hBar = document.getElementById('harvestBar');
  hVal.innerText = `${harvestPercentage}%`;
  hBar.style.width = `${harvestPercentage}%`;

  if (harvestPercentage < 30) {
    hVal.className = "metric-value risk-safe";
    hBar.style.backgroundColor = "#16a34a";
  } else if (harvestPercentage < 70) {
    hVal.className = "metric-value risk-warning";
    hBar.style.backgroundColor = "#d97706";
  } else {
    hVal.className = "metric-value risk-danger";
    hBar.style.backgroundColor = "#dc2626";
  }

  // 2. Parse the Choice response (main attack vector)
  // In the response: jevOutput.risk_category.choice holds a key string (e.g. "safe")
  const categoryKey = (jevOutput.risk_category && jevOutput.risk_category.choice) 
    ? jevOutput.risk_category.choice 
    : "safe";
  
  // Mapping of keys to user-friendly language
  const categoryLabels = {
    "safe": "Safe",
    "insecure_form": "Insecure form (HTTP)",
    "suspicious_scripts": "Suspicious scripts",
    "clickjacking_risk": "Clickjacking risk (iframe)",
    "mixed_content": "Mixed content (HTTP/HTTPS)",
    "credential_harvest": "Deceptive credential harvesting",
    "data_exfiltration": "Data exfiltration to third-party domains",
    "deceptive_ui": "Deceptive UI"
  };

  const category = categoryLabels[categoryKey] || categoryKey;
  const cVal = document.getElementById('categoryVal');
  cVal.innerText = category;
  cVal.className = "metric-value " + (categoryKey === "safe" ? "risk-safe" : "risk-danger");

  // 3. Parse the Score response (risk index)
  // In the response: jevOutput.severity_score.score holds a float (e.g. 1.54)
  // The criteria array spans 0..4 (5 levels), so Jev computes the index from 0.
  // We add 1 so the user-facing scale runs from 1 to 5.
  const rawScore = (jevOutput.severity_score && typeof jevOutput.severity_score.score === 'number') 
    ? jevOutput.severity_score.score 
    : 0.0;
  
  const score = Math.min(5, Math.max(1, Math.round(rawScore + 1))); 
  
  const sVal = document.getElementById('scoreVal');
  const sBar = document.getElementById('scoreBar');
  sVal.innerText = `${score} / 5`;
  
  const scorePct = (score / 5) * 100;
  sBar.style.width = `${scorePct}%`;
  sBar.style.backgroundColor = score >= 4 ? "#dc2626" : (score >= 3 ? "#d97706" : "#16a34a");
}



