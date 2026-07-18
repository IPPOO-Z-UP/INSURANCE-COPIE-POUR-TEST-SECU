# Sentinel Security Journal

## 2026-06-13 - Insecure Randomness in OTP and Matricule Generation
**Vulnerability:** Use of `Math.random()` for security-sensitive tokens and identifiers (such as agent matricules and 6-digit SMS verification OTPs). This is cryptographically insecure and makes the codes highly predictable, exposing users to OTP bypasses or account takeovers.
**Learning:** Standard Math.random() is pseudo-random and uses a deterministic algorithm with a predictable seed in JavaScript runtime environments. Developers often use it for quick numeric generation without realizing the security implications in authentication and identification features.
**Prevention:** Always use cryptographically secure random number generators such as `crypto.getRandomValues()` for any security-sensitive OTPs, tokens, passwords, and identifiers. Define standard utility wrappers (e.g. `secureRandomInt`) to make it easy for developers to safely obtain random numbers.
