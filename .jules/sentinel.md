## 2026-05-30 - Insecure Randomness and Information Leakage
**Vulnerability:** The backend was using `Math.random()` for security-sensitive purposes including OTP generation, agent matricule generation, and internal identifier suffixes. Additionally, sensitive handlers were leaking internal error details to clients.
**Learning:** Legacy code often relies on `Math.random()` for convenience, which is predictable and not suitable for security purposes. Direct exposure of exceptions in API responses can leak database schema details or internal logic.
**Prevention:** Always use `crypto.getRandomValues()` for security-sensitive randomness. Implement a centralized error masking utility like `safeError` to ensure internal details never reach the client while maintaining full logs on the server.
