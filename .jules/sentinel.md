# Sentinel Security Journal

## 2026-07-06 - Secure Randomness and Error Handling
**Vulnerability:** Use of `Math.random()` for security-sensitive values (OTPs, matricules, IDs) and information leakage via detailed error messages in API responses.
**Learning:** The codebase relied on insecure PRNG for authentication secrets (OTPs) and internal identifiers, which could be predictable. It also leaked internal stack traces and database error messages directly to the client.
**Prevention:** Use `crypto.getRandomValues()` (CSPRNG) for all security-sensitive random values. Implement a centralized `safeError` utility to log internal details server-side while returning generic messages and correlation IDs to the client.
