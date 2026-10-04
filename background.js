const TYPESAFE_API_URL = "https://api.typesafe.ai/v1/systemone";
const SCAN_PAGE_MENU_ID = "jev-scan-page";
const MISSING_KEY_ERROR = "API key is missing. Open the extension popup and save it in the settings.";

// The context menu is created once on extension install/update.
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: SCAN_PAGE_MENU_ID,
    title: "Jev: check page safety",
    contexts: ["page", "selection"]
  });
});

// Clicking the menu triggers a full scan on the active tab.
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === SCAN_PAGE_MENU_ID && tab && tab.id) {
    chrome.tabs.sendMessage(tab.id, { action: "scan_page_from_menu" }, () => {
      void chrome.runtime.lastError;
    });
  }
});

// Reads the Jev API key from chrome.storage.local (set in the popup settings).
function getApiKey() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["jevApiKey"], (stored) => {
      resolve((stored.jevApiKey || "").trim());
    });
  });
}

// Single TypeSafe request strictly per the API specification.
// Returns the answers object or throws with an error message.
async function askJev(userApiKey, state, questions) {
  const response = await fetch(TYPESAFE_API_URL, {
    method: "POST",
    mode: "cors",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${userApiKey}`
    },
    body: JSON.stringify({
      model: "jev-latest",
      state: JSON.stringify(state), // Send the state as a valid JSON string
      questions: questions
    })
  });

  // Safely intercept any API-side validation errors
  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`API ${response.status}: ${errText}`);
  }

  const result = await response.json();
  if (!result || !result.answers) {
    throw new Error("Malformed response format from TypeSafe");
  }
  return result.answers;
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyze_page") {
    
    (async () => {
      try {
        let cleanState = request.pageData;

        // The API key lives in chrome.storage.local and is set in the popup settings.
        const userApiKey = await getApiKey();
        if (!userApiKey) {
          sendResponse({ success: false, error: MISSING_KEY_ERROR });
          return;
        }
        
        // Guard against oversized context (32k token limit)
        if (cleanState && cleanState.scripts && cleanState.scripts.length > 50) {
          cleanState.scripts = cleanState.scripts.slice(0, 50);
        }

        // Build the question structure strictly per the TypeSafe API specification
        const questions = {
          // 1. Noul: binary question. Accepts instructions and optional criteria
          phishing_prob: {
            type: "noul",
            instructions: "Is this web page structure indicative of a phishing template or deceptive credentials harvesting?"
          },
          
          // 1b. Noul: deceptive credential harvesting
          credential_harvest: {
            type: "noul",
            instructions: "Does this page contain forms or UI patterns designed to deceptively harvest sensitive credentials (passwords, card data, tokens)?"
          },

          // 2. Choice: criteria must be an object describing every option!
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
          
          // 3. Score: criteria must be an array (at least 2 items, lowest to highest)
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

        const answers = await askJev(userApiKey, cleanState, questions);
        sendResponse({ success: true, result: answers });

      } catch (error) {
        console.error("Jev AI Fetch Error:", error);
        sendResponse({ success: false, error: error.message });
      }
    })();

    return true; // Keep the async channel open for popup.js
  }

  // Asks Jev AI one binary (noul) question per locally found vulnerability:
  // can this vulnerability be used to attack this web page?
  if (request.action === "assess_findings") {
    (async () => {
      try {
        const findings = (request.pageData && request.pageData.findings) || [];
        if (!findings.length) {
          sendResponse({ success: true, answers: {} });
          return;
        }

        const userApiKey = await getApiKey();
        if (!userApiKey) {
          sendResponse({ success: false, error: MISSING_KEY_ERROR });
          return;
        }

        // One question per finding, keyed by the finding id.
        const questions = {};
        findings.forEach((finding) => {
          questions[finding.id] = {
            type: "noul",
            instructions:
              "Can this vulnerability be used to attack this web page? " +
              `Vulnerability: ${finding.reason}. ` +
              `Details: ${finding.detail || finding.selector}.`
          };
        });

        const answers = await askJev(userApiKey, request.pageData, questions);
        sendResponse({ success: true, answers });
      } catch (error) {
        console.error("Jev AI finding assessment error:", error);
        sendResponse({ success: false, error: error.message });
      }
    })();

    return true; // Keep the async channel open for content.js
  }
});
