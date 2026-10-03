const TYPESAFE_API_KEY = ""; // Укажите ваш ключ
const TYPESAFE_API_URL = "https://api.typesafe.ai/v1/systemone";

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyze_page") {
    
    (async () => {
      try {
        let cleanState = request.pageData;
        
        // Защита от перегрузки контекста (лимит 32k токенов)
        if (cleanState && cleanState.scripts && cleanState.scripts.length > 50) {
          cleanState.scripts = cleanState.scripts.slice(0, 50);
        }

        // Формируем структуру вопросов строго по спецификации TypeSafe API
        const questions = {
          // 1. Noul: бинарный вопрос. Принимает instructions и необязательный criteria
          phishing_prob: {
            type: "noul",
            instructions: "Is this web page structure indicative of a phishing template or deceptive credentials harvesting?"
          },
          
          // 1b. Noul: сбор учётных данных обманным путём
          credential_harvest: {
            type: "noul",
            instructions: "Does this page contain forms or UI patterns designed to deceptively harvest sensitive credentials (passwords, card data, tokens)?"
          },

          // 2. Choice: criteria должен быть объектом с описанием каждой опции!
          risk_category: {
            type: "choice",
            instructions: "What is the primary security vulnerability or risk vector present on this page?",
            criteria: {
              "safe": "The page configuration has no visible structural security issues.",
              "insecure_form": "The page has forms collecting sensitive attributes like login or password via insecure HTTP.",
              "suspicious_scripts": "The page embeds JavaScript files originating from blacklisted or untrusted external domains.",
              "clickjacking_risk": "The layout features un-sandboxed or hidden iframes loaded from external sources.",
              "mixed_content": "The website loads critical operational assets via non-SSL links.",
              "credential_harvest": "The page presents forms or UI intentionally designed to deceptively harvest passwords, tokens or payment data.",
              "data_exfiltration": "Page scripts appear to collect and transmit form or user data to untrusted third parties.",
              "deceptive_ui": "The visual layout uses overlays, hidden elements or fake dialogs to mislead the user."
            }
          },
          
          // 3. Score: criteria должен быть массивом (минимум 2 элемента, от низшего к высшему)
          severity_score: {
            type: "score",
            instructions: "Rate the overall security risk level of this page layout and scripts configuration.",
            criteria: [
              "Level 1: Absolute safe, compliant structure",
              "Level 2: Minor configuration anomalies observed",
              "Level 3: Moderate policy violations detected",
              "Level 4: High probability of actively malicious design",
              "Level 5: Critical structural threat requiring immediate block"
            ]
          }
        };

        const response = await fetch(TYPESAFE_API_URL, {
          method: "POST",
          mode: "cors",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${TYPESAFE_API_KEY}`
          },
          body: JSON.stringify({
            model: "jev-latest",
            state: JSON.stringify(cleanState), // Передаем состояние как валидную JSON строку
            questions: questions
          })
        });

        // Безопасный перехват любых ошибок валидации со стороны API
        if (!response.ok) {
          const errText = await response.text();
          sendResponse({ success: false, error: `API ${response.status}: ${errText}` });
          return;
        }

        const result = await response.json();
        
        if (result && result.answers) {
          sendResponse({ success: true, result: result.answers });
        } else {
          sendResponse({ success: false, error: "Malformed response format from TypeSafe" });
        }

      } catch (error) {
        console.error("Jev AI Fetch Error:", error);
        sendResponse({ success: false, error: error.message });
      }
    })();

    return true; // Держим асинхронный канал открытым для popup.js
  }
});
