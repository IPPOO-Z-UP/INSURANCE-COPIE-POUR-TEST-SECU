## 2026-05-30 - Security hardening of backend handlers

**Vulnerability:** Information leakage via verbose error messages and weak random number generation for security-sensitive identifiers (agent matricules and OTPs).

**Learning:** The application was using `Math.random()` for critical values like agent matricules and OTP codes, which is not cryptographically secure. Additionally, some backend handlers were returning raw error objects to the client, which could expose internal system details.

**Prevention:** Always use `crypto.getRandomValues()` (via `secureRandomInt`) for security-sensitive randomness. Use a centralized `safeError` utility to log the actual error internally while returning a generic, safe message to the client.
