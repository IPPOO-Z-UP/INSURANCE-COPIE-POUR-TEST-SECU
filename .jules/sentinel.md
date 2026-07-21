# Sentinel Security Journal

## 2026-05-29 - Cryptographically Secure Randomness Migration

**Vulnerability:** Weak pseudo-random number generation using standard `Math.random()` in backend functions. This was used to generate security-sensitive tokens, user passwords, one-time passwords (OTPs), unique agent matricules, payment IDs, audit trail identifiers, and webhook log IDs.

**Learning:** Standard Math.random() is a PRNG (Pseudo-Random Number Generator) designed for performance, not cryptographic security. It can be easily predicted or reverse-engineered by an attacker who observes a sequence of generated values. For example, predicting OTPs or temporary registration/seeding passwords can compromise authentication, and predictable audit hashes can lead to undetected log tampering.

**Prevention:** Always use cryptographically secure random number generators (CSPRNGs) such as `crypto.getRandomValues()` for any value that must remain unpredictable, secret, or globally unique in security-sensitive contexts. This implementation encapsulates secure generation into robust `secureRandomInt` and `secureRandomSuffix` helpers.
