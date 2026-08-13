# Sentinel Security Journal

## 2026-08-13 - Secure Randomness for Critical Secrets (OTP and Agent Matricules)
**Vulnerability:** Use of predictable `Math.random()` for generating One-Time Passwords (OTPs) and Agent Matricules in the backend API. Since `Math.random()` is not cryptographically secure, the state of the PRNG can be reconstructed by an attacker who observes several consecutive generated values, allowing them to predict future OTP codes or guess valid agent matricules.
**Learning:** Developers often default to `Math.random()` for simple range-based integer generation because standard platform libraries lack a simple, secure range-based helper. For highly critical features like MFA/authentication OTPs and distinct actor matricules, we must use a cryptographically secure random number generator (CSPRNG) based on the Web Crypto API (`crypto.getRandomValues`).
**Prevention:** Avoid `Math.random()` entirely for any security-sensitive operations. Always use the Web Crypto API via `crypto.getRandomValues` to construct a cryptographically secure alternative.
