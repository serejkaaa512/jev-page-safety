# Jev Page Safety

Chrome (Manifest V3) extension for security engineers. It scans a page, points out
DOM elements that can be compromised, and asks the TypeSafe Jev AI model for a risk
assessment of the page structure. Jev AI is the only analysis backend.

## What it does

1. **Local heuristic scan** (`content.js`) walks the DOM and flags
   compromiseable elements directly on the page:

   | Finding | Severity | What is flagged |
   | :--- | :--- | :--- |
   | `insecure_credentials` | critical | Password form on an HTTP page |
   | `credentials_exfiltration` | high | Password form posting to a third-party origin |
   | `insecure_action` | high | Form posting over plain HTTP |
   | `clickjacking_risk` | high | iframe without a `sandbox` attribute |
   | `mixed_content` | high | HTTP resource loaded inside an HTTPS page |
   | `javascript_link` | high | `javascript:` link |
   | `data_link` | medium | `data:` link (content substitution) |
   | `reverse_tabnabbing` | medium | `target="_blank"` without `rel="noopener"` |
   | `third_party_frame` | medium | Cross-origin iframe |
   | `meta_redirect` | medium | Automatic redirect via `meta refresh` |
   | `third_party_script` | low | Third-party script without Subresource Integrity |

2. **Jev AI assessment** (`background.js`) sends the collected page structure to
   `https://api.typesafe.ai/v1/systemone` and renders the typed answers:
   phishing probability, credential-harvest probability, risk category, and a
   1–5 severity score.

## Where results appear

- **On page**: a findings panel (bottom-right) showing the page-structure summary and
  the list of flagged elements with highlight + click-to-scroll, plus a Jev AI summary
  panel (bottom-left) with the AI risk metrics. A context-menu item ("Jev: проверить
  безопасность страницы") triggers the full in-page scan.
- **Popup** (`popup.html` / `popup.js`): settings and scan button, plus the Jev AI
  metrics (phishing, credential harvest, risk category, severity score). The structural
  summary and the element list live on the page only.

## Settings

Stored in `chrome.storage.local`:

- `jevApiKey` — TypeSafe Jev API token.
- `jevAutoRemoveDangerous` — when enabled, removes flagged elements automatically on
  page load. Off by default.

Destructive actions (remove one / remove all findings) mutate the live DOM and are
intended for controlled analysis only.

## Files

- `manifest.json` — MV3 manifest, permissions, content script registration.
- `content.js` — DOM collection, local heuristic detection, on-page UI.
- `background.js` — Jev AI request, API-key handling, context menu.
- `popup.html` / `popup.js` — extension popup UI and rendering.
- `styles.css` — styles for the in-page findings and Jev AI panels.

## Install (developer mode)

1. Open `chrome://extensions`, enable **Developer mode**.
2. **Load unpacked** → select this folder.
3. Open the popup, paste your TypeSafe Jev API token, save.
