# Sentinel's Security Journal

## 2026-03-05 - Weak Random Number Generation and Error Information Leakage
**Vulnerability:** Use of `Math.random()` for critical security operations (OTP codes, agent matricules, payment/audit IDs, and temporary passwords) and direct output of internal exceptions (`${err}`) in server responses.
**Learning:** `Math.random()` in JS/TS is cryptographically insecure and predictable, exposing authentication flows and identifiers to bypass or collision risks. Returning raw error objects leaks internal details to clients.
**Prevention:** Always use `crypto.getRandomValues()` for security-sensitive random generations and implement a centralized `safeError` utility to log the raw exception on the server while returning a user-friendly generic message.
