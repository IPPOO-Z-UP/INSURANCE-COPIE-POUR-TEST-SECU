# Sentinel Security Journal

## 2026-05-25 - Replace Predictable Math.random PRNG with Web Crypto
**Vulnerability:** Use of `Math.random()` for security-critical values including 6-digit phone OTPs, temporary passwords, agent matricules, and audit/token IDs.
**Learning:** `Math.random()` uses a pseudo-random number generator that is not cryptographically secure and can be forecasted by an attacker observing sequence outputs.
**Prevention:** Always use Web Crypto (`crypto.getRandomValues`) via dedicated helper utilities (`secureRandomInt` and `secureRandomSuffix`) for security tokens, codes, and IDs across backend services.
