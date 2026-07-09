## 2025-05-14 - Replace Math.random() with CSPRNG and mask internal errors
**Vulnerability:** Use of insecure `Math.random()` for security tokens (OTPs, passwords) and identifiers, along with potential information leakage in backend error responses.
**Learning:** `Math.random()` is not cryptographically secure and can lead to predictable values in a high-stakes assurance platform. Directly returning server errors can expose internal system details to attackers.
**Prevention:** Always use `crypto.getRandomValues()` for security-sensitive randomness and implement a generic `safeError` utility to mask backend implementation details.
