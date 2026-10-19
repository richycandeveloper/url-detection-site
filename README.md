# PhishGuard: AI-Powered Real-Time Phishing Detection and Prevention System
**Case study: MTN Enugu.** Final-year Computer Science project (frontend prototype).

## Objectives
Demonstrate URL phishing analysis, user awareness, reporting and alerting in a clean dashboard, and prepare the structure for a real ML backend.

## Features
Landing page with scroll animations and a mobile toggle menu; dashboard (Overview, URL Scanner, Scan History, Threat Reports, Security Alerts, Safety Center, Settings); search, filter, sort; confirmation dialogs; light/dark theme; responsive layout.

## Technologies
HTML5, CSS3, vanilla JavaScript. No frameworks, no build step.

## Folder structure
```
phishing-detection-system/
  index.html
  css/style.css
  js/app.js
  assets/images/
  assets/icons/logo.svg
  README.md
```

## Run locally
Open `index.html` in a modern browser. No server is needed.

## Demonstration detection algorithm
`ruleBasedDetector()` in `js/app.js` adds points for: HTTP (20), length over 75 chars (10), IP host (30), suspicious terms (8 each, max 24), many subdomains (15), punycode (25), "@" in URL (25), unusual port (15), encoded characters (10), many hyphens (8), and "MTN" in an unofficial-looking domain (20). The total is capped at 100. Under 25 = "Low risk signals detected", 25-54 = "Suspicious URL", 55+ = "High-risk URL". A low score is never labelled "safe". **This is a transparent rule set, not a trained AI model.** The thresholds are illustrative and have not been evaluated for accuracy.

## localStorage
Scans, reports, alerts and settings are stored in the browser's localStorage under `pg_*` keys. It is private to one browser on one device, can be cleared by the user, and is **not a shared database**.

## Security limitations
No live threat intelligence, no page inspection, no authentication, no backend, no MTN integration. Reports are not sent to anyone. User input is rendered with `textContent` to prevent HTML injection. Links are never opened automatically.

## Future integration
1. **Detection API:** replace the body of `detectUrl()` with a `fetch` call to your server; keep the returned object shape.
2. **ML model:** train and evaluate a classifier (for example on public phishing URL datasets), serve it behind the API, and report real metrics.
3. **Supabase:** add Auth, a PostgreSQL `scans`/`reports`/`alerts` schema with Row Level Security (rows owned by `auth.uid()`), and replace the `Store` wrapper with Supabase calls. Use only the public anon key in the frontend, never a service-role key.
4. **Threat intelligence / telecom data:** integrate only authorized sources, server-side, with proper agreements.
