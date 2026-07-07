## 2026-07-07 - Insecure Randomness and Information Leakage in Hono/Deno Backend
**Vulnerability:** Use of `Math.random()` for security-sensitive tokens (OTP, IDs, passwords) and direct leakage of internal errors/exceptions to the client.
**Learning:** Even in modern TypeScript environments, the lack of centralized security utilities leads developers to reach for insecure defaults like `Math.random()` or raw `err.message` in catch blocks.
**Prevention:** Implement and enforce the use of `secureRandomInt`, `secureRandomSuffix`, and `safeError` helpers. Auditing with grep for `Math.random()` should be part of the security CI.
