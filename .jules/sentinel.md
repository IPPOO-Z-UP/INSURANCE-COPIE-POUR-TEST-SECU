# Sentinel's Security Journal

## 2025-05-25 - Constant-Time Secret and Signature Verification

**Vulnerability:**
Webhook verification tokens (KkiaPay `X-Kkiapay-Secret`, MTN MoMo `x-callback-key`), calculated HMAC signatures (CinetPay, FedaPay), and scheduled tasks authorization (`CRON_SECRET`) were evaluated with standard JavaScript equality operators (`!==`). Because string equality comparison is variable-time and terminates immediately upon discovering the first mismatched character, subtle response latency differences could theoretically leak secret characters to an attacker via timing analysis.

**Learning:**
Even with HTTPS and standard rate limiting, timing side-channels in endpoints accepting secret tokens or cryptographic signatures present a subtle risk. Fixed-length digestion (such as SHA-256) followed by bitwise XOR accumulation provides a constant-time comparison helper that works uniformly across diverse secret lengths and Deno/Web Crypto runtime environments without requiring external C-bindings or Node.js-only modules (`crypto.timingSafeEqual`).

**Prevention:**
Always compare security tokens, HMAC signatures, and webhook shared secrets using `safeCompareSecret` rather than `===` or `!==`. Ensure that `undefined` or empty tokens are strictly rejected prior to comparison.
