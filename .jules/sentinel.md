## 2026-05-29 - Insecure Randomness and Information Leakage

**Vulnerability:** The application used `Math.random()` for security-sensitive operations, including generating 6-digit phone OTPs, agent matricules, and temporary passwords. Additionally, API handlers were returning internal error details and stack traces to the client in catch blocks.

**Learning:** `Math.random()` is not cryptographically secure and its output can be predictable, which is a high risk for authentication tokens and credentials. Leaking internal error details can expose the application's internal structure and potentially sensitive data to attackers.

**Prevention:** Always use a cryptographically secure random number generator (CSPRNG) like `crypto.getRandomValues()` for security-sensitive data. Implement a unified `safeError` utility to log internal details server-side while returning generic messages to the client.
