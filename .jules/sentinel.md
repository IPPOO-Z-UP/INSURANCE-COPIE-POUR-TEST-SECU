## 2026-05-30 - Insecure Randomness and Information Leakage in Backend

**Vulnerability:** The backend used `Math.random()` for security-sensitive operations such as generating OTPs and agent matricules, which are not cryptographically secure. Additionally, several error handlers returned raw error messages (`${err}`) to the client, potentially leaking internal system details.

**Learning:** The use of `Math.random()` is common but dangerous for security purposes. Raw error message return is also a common oversight that can lead to information disclosure. Standardization of these security-critical functions is necessary.

**Prevention:** Always use `crypto.getRandomValues()` for security-sensitive randomness. Implement a `safeError` utility to log the actual error internally while returning a generic message to the user.
