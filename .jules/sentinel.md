## 2025-05-15 - Security Hardening: CSPRNG and Error Sanitization
**Vulnerability:** Predictable security tokens due to `Math.random()` and information exposure via raw error responses.
**Learning:** The codebase used `Math.random()` for generating 6-digit OTPs and agent matricules, which are predictable by attackers. Additionally, several catch blocks returned raw error details to clients in 500 responses.
**Prevention:** Use `secureRandomInt` (using `crypto.getRandomValues`) for all security-sensitive identifiers and tokens. Use the `safeError` utility to ensure internal errors are logged on the server but generic safe messages are returned to the client.
