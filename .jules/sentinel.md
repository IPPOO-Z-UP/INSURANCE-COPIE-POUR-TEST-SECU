# Sentinel Security Journal

## 2026-06-12 - Secure Randomness for Phone OTP Generation
**Vulnerability:** Phone OTP generation in `/phone/otp/send` utilized standard `Math.random()`, which is a pseudo-random number generator (PRNG) that is not cryptographically secure and can be vulnerable to internal state reconstruction and prediction attacks.
**Learning:** Security-sensitive credentials and tokens (such as one-time SMS verification codes and secrets) must be generated using `crypto.getRandomValues` Web Crypto API rather than `Math.random()`.
**Prevention:** Audit all randomness generation endpoints across backend functions to ensure `crypto.getRandomValues()` is used whenever generating authentication or verification tokens, credentials, or IDs.
