# Sentinel's Journal

## 2025-05-15 - Initial Audit
**Vulnerability:** Use of `Math.random()` for security-sensitive values (OTP, agent matricules) and verbose error messages leaking internal details.
**Learning:** The codebase relies on insecure pseudo-randomness for sensitive operations and often returns raw error objects in API responses.
**Prevention:** Use `crypto.getRandomValues()` for security-sensitive randomness and implement a `safeError` utility to mask internal errors from users.
