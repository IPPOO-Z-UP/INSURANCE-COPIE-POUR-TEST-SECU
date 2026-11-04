## 2026-05-30 - Timing attack vulnerability in webhook signatures and cron secret verification

**Vulnerability:** In `Backend API/functions/server/index.tsx`, webhook secrets (`KKIAPAY_SECRET`, `CINETPAY_SECRET_KEY`, `FEDAPAY_WEBHOOK_SECRET`, `MTN_MOMO_CALLBACK_KEY`) and scheduled cron secrets (`CRON_SECRET`) were validated using strict standard string equality (`!==` or `===`). Standard JavaScript string comparison terminates as soon as a mismatch is detected, leaking secret character matches via timing side-channels and allowing brute-force byte-by-byte reconstruction of secrets.

**Learning:** Webhook endpoints and cron entry points are exposed publicly without upstream IP whitelisting. When verifying cryptographic tokens or pre-shared secret keys in edge functions, standard comparison operations leak timing information. In Deno/browser Web Crypto environments where Node's `crypto.timingSafeEqual` may not be directly available, digests of both strings must be computed using `crypto.subtle.digest("SHA-256", ...)` and compared using a constant-time bitwise XOR loop over the fixed-length byte arrays.

**Prevention:** Always compare secret keys, webhook signatures, or shared secrets using a constant-time comparison helper like `safeCompareSecret`. Never compare secret tokens directly with `===` or `!==`.
