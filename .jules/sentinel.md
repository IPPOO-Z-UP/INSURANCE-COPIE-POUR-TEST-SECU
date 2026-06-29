## 2026-06-29 - [HIGH] Insecure Randomness in Security-Sensitive Operations
**Vulnerability:** Extensive use of `Math.random()` for generating OTP codes, agent matricules, session IDs (jti), and various internal identifiers.
**Learning:** `Math.random()` in many environments (including V8 used by Deno/Node) is PRNG-based and not cryptographically secure, making generated secrets potentially predictable if the internal state of the generator is leaked or guessed.
**Prevention:** Always use `crypto.getRandomValues()` or `crypto.randomUUID()` for security-sensitive randomness. Reusable `secureRandomInt` and `secureRandomString` utilities have been added to the core server logic.
