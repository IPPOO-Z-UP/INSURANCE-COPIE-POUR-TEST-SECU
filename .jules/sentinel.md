## 2026-05-30 - Cryptographically Secure Randomness for OTP & Agent Matricules
**Vulnerability:** Use of `Math.random()` in security-sensitive backend flows (OTP phone verification and Agent Matricule generation).
**Learning:** `Math.random()` uses a pseudo-random number generator (PRNG) that is deterministic and predictable given enough outputs.
**Prevention:** Always use Web Crypto (`crypto.getRandomValues`) via helper utilities like `secureRandomInt` for OTPs, tokens, passwords, and identifiers.
