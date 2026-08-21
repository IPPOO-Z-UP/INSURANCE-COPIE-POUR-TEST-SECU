## 2026-05-30 - Cryptographically Secure Randomness for OTPs and Identifiers

**Vulnerability:** Predictable pseudo-random numbers (`Math.random()`) were used in backend API flows for generating 6-digit phone OTP codes (`/phone/otp/send`) and agent matricules (`resolveAgentMatricule`). `Math.random()` relies on PRNG algorithms (e.g., xorshift128+) whose state can be determined from prior outputs, allowing attackers to predict SMS OTP codes or guess generated identifiers.

**Learning:** When generating security-sensitive data such as OTP codes, secret tokens, or unique identifiers, built-in standard library PRNGs like `Math.random()` do not provide cryptographic entropy.

**Prevention:** Use `crypto.getRandomValues()` with rejection sampling (to avoid modulo bias) via `secureRandomInt` and `secureRandomSuffix` helpers for all security-sensitive random value generation in the backend.
