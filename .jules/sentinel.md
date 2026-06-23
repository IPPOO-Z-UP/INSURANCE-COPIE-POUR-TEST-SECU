## 2025-05-30 - [HTML Injection in Emails & Error Leakage]
**Vulnerability:** User-controlled data (names, labels, notes) was directly interpolated into HTML email templates, and raw error objects (including stack traces) were returned to clients in 500 responses.
**Learning:** Common in rapid development using template literals; missing a centralized escaping utility led to inconsistent security coverage.
**Prevention:** Always use a global `esc()` helper for HTML interpolation and a `safeError()` wrapper for catch blocks to log detailed errors internally while returning generic messages to users.
