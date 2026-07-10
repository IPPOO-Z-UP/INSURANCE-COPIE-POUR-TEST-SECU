## 2025-06-21 - Secure Randomness and Error Handling Patterns
**Vulnerability:** Use of `Math.random()` for security-sensitive values (OTP, referral codes, IDs) and exposure of raw error messages in the signup flow.
**Learning:** The project is a micro-assurance platform for Benin where predictability of codes (OTPs) or IDs could lead to account takeover or enumeration. Raw error messages can leak database structure or internal logic.
**Prevention:** Always use `secureRandomInt` (based on `crypto.getRandomValues`) for numeric codes and `secureRandomSuffix` for random strings. Use the `safeError` utility for all user-facing endpoints to mask internal details while logging them for developers.
