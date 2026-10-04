// ---------------------------------------------------------------------------
// Настройки: API-ключ TypeSafe Jev сохраняется в chrome.storage.local
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
    saveBtn.textContent = 'Сохранено ✓';
    clearTimeout(saveBtnTimer);
    saveBtnTimer = setTimeout(() => {
      saveBtn.classList.remove('saved');
      saveBtn.textContent = 'Сохранить настройки';
    }, 1600);
    showSaveStatus(key ? 'API-ключ сохранён' : 'API-ключ очищен', true);
  });
});

// ---------------------------------------------------------------------------
// Автоудаление опасных элементов при загрузке страницы (по умолчанию выключено).
// Настройка читается content.js и применяется без перезагрузки страницы.
// ---------------------------------------------------------------------------
const autoRemoveInput = document.getElementById('autoRemove');

chrome.storage.local.get(['jevAutoRemoveDangerous'], (result) => {
  autoRemoveInput.checked = !!result.jevAutoRemoveDangerous;
});

autoRemoveInput.addEventListener('change', () => {
  chrome.storage.local.set({ jevAutoRemoveDangerous: autoRemoveInput.checked }, () => {
    showSaveStatus(autoRemoveInput.checked ? 'Автоудаление включено' : 'Автоудаление выключено', true);
  });
});

document.getElementById('scanBtn').addEventListener('click', async () => {
  const scanBtn = document.getElementById('scanBtn');
  const loader = document.getElementById('loader');
  const resultBox = document.getElementById('resultBox');

  scanBtn.disabled = true;
  loader.style.display = 'block';
  resultBox.style.display = 'none';

  // 1. Получаем активную вкладку браузера
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  if (!tab) {
    alert("Не удалось найти активную вкладку.");
    resetUI();
    return;
  }

  // 2. Отправляем сигнал в content.js для сбора структуры DOM
  chrome.tabs.sendMessage(tab.id, { action: "scan_page" }, (response) => {
    // lastError возникает, если content script недоступен (страница не обновлена
    // после установки расширения или это служебная страница).
    if (chrome.runtime.lastError || !response || !response.success) {
      alert("Не удалось просканировать страницу. Обновите вкладку и попробуйте снова.");
      resetUI();
      return;
    }

    // 3. Отправляем очищенный JSON в background.js для запроса к Jev AI
    chrome.runtime.sendMessage({ action: "analyze_page", pageData: response.data }, (apiResponse) => {
      resetUI();

      // Если service worker не ответил (порт закрылся), callback приходит с lastError.
      if (chrome.runtime.lastError) {
        alert("Сервис Jev AI недоступен: " + chrome.runtime.lastError.message);
        return;
      }
      if (apiResponse && apiResponse.success) {
        renderResults(apiResponse.result);
      } else {
        alert("Ошибка при обращении к Jev AI: " + (apiResponse?.error || "Unknown error"));
      }
    });
  });
});

function resetUI() {
  document.getElementById('scanBtn').disabled = false;
  document.getElementById('loader').style.display = 'none';
}

// 4. Парсинг строго типизированного ответа от Jev AI и отрисовка
function renderResults(jevOutput) {
  const resultBox = document.getElementById('resultBox');
  resultBox.style.display = 'block';

  // 1. Разбираем ответ Noul (Угроза фишинга)
  // В ответе: jevOutput.phishing_prob.noul содержит значение (например, 0.23)
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
    pBar.style.backgroundColor = "#16a34a"; // Зеленый
  } else if (phishingPercentage < 70) {
    pVal.className = "metric-value risk-warning";
    pBar.style.backgroundColor = "#d97706"; // Желтый
  } else {
    pVal.className = "metric-value risk-danger";
    pBar.style.backgroundColor = "#dc2626"; // Красный
  }

  // 1b. Разбираем ответ Noul (Обманный сбор учётных данных)
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

  // 2. Разбираем ответ Choice (Основной вектор атаки)
  // В ответе: jevOutput.risk_category.choice содержит строку-ключ (например, "safe")
  const categoryKey = (jevOutput.risk_category && jevOutput.risk_category.choice) 
    ? jevOutput.risk_category.choice 
    : "safe";
  
  // Маппинг ключей на понятный для пользователя язык
  const categoryLabels = {
    "safe": "Безопасно",
    "insecure_form": "Незащищенная форма (HTTP)",
    "suspicious_scripts": "Подозрительные скрипты",
    "clickjacking_risk": "Риск Clickjacking (iframe)",
    "mixed_content": "Смешанный контент (HTTP/HTTPS)",
    "credential_harvest": "Обманный сбор учётных данных",
    "data_exfiltration": "Утечка данных на сторонние домены",
    "deceptive_ui": "Вводящий в заблуждение интерфейс"
  };

  const category = categoryLabels[categoryKey] || categoryKey;
  const cVal = document.getElementById('categoryVal');
  cVal.innerText = category;
  cVal.className = "metric-value " + (categoryKey === "safe" ? "risk-safe" : "risk-danger");

  // 3. Разбираем ответ Score (Индекс опасности)
  // В ответе: jevOutput.severity_score.score содержит дробное число (например, 1.54)
  // Так как массив критериев был от 0 до 4 (5 уровней), Jev считает индекс от 0.
  // Прибавим 1, чтобы шкала для пользователя была от 1 до 5.
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



