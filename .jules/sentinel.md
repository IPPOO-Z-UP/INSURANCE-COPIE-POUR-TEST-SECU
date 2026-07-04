## 2025-05-30 - Insecure Randomness and Verbose Error Handling
**Vulnerability:** Use of `Math.random()` for security-sensitive values (OTPs, matricules, IDs) and exposure of internal error details in API responses.
**Learning:** Standard JavaScript `Math.random()` is not cryptographically secure and its output can be predictable. Verbose error messages in production can leak internal logic and system state.
**Prevention:** Always use `crypto.getRandomValues()` (via a utility like `secureRandomInt`) for security-sensitive randomness. Implement a `safeError` utility to log detailed errors internally while returning generic, safe messages to the client.
