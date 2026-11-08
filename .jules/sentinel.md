# Sentinel Security Journal

## 2026-06-13 - Constant-Time Secret Verification Against Timing Attacks
**Vulnerability:** Endpoints handling sensitive cron triggers (`CRON_SECRET`), payment provider webhooks (`KKIAPAY_SECRET`, `CINETPAY_SECRET_KEY`, `FEDAPAY_WEBHOOK_SECRET`, `MTN_MOMO_CALLBACK_KEY`), and staff onboarding codes (`AGENT_SIGNUP_CODE`) compared incoming tokens and signatures using standard string comparison operators (`!==`).
**Learning:** Standard JavaScript string equality checks short-circuit on the first mismatched byte and leak character match timings, potentially exposing secrets or signatures via remote timing attacks. Because the backend runs on Deno/Edge with Web Crypto available, hashing candidate strings with SHA-256 before performing a bitwise XOR comparison ensures fixed-time, fixed-length comparisons without adding external dependencies.
**Prevention:** Whenever comparing bearer tokens, webhook signatures, or shared secrets, always compare using `safeCompareSecret` or equivalent constant-time comparisons rather than standard equality operators.
