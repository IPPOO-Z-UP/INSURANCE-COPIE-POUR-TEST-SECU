## 2026-06-13 - Insecure PRNG in OTP Code Generation & Missing Global Security Controls

**Vulnerability:** The SMS OTP endpoint (`/phone/otp/send`) generated 6-digit authentication verification codes using `Math.random()`, which is a non-cryptographically secure PRNG susceptible to state prediction. Additionally, responses lacked standard defensive HTTP security headers and unhandled exceptions were not suppressed globally.

**Learning:** When writing lightweight backend utility endpoints, standard PRNG functions like `Math.random()` can mistakenly be used for authentication codes. Using Web Crypto `crypto.getRandomValues()` provides cryptographically secure randomness.

**Prevention:** Always use `crypto.getRandomValues()` for security-sensitive tokens, verification codes, and secrets. Enforce defense-in-depth via global HTTP security headers and `app.onError` exception handlers on the primary Hono router.
