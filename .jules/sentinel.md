# Sentinel's Security Journal

This journal tracks critical security learnings, vulnerability patterns, and prevention strategies for the project.

## 2025-05-15 - Insecure Randomness and Information Leakage
**Vulnerability:** Use of `Math.random()` for sensitive identifiers (OTPs, matricules) and exposure of internal error details in API responses.
**Learning:** `Math.random()` is not cryptographically secure. Returning raw error messages can leak stack traces or internal logic.
**Prevention:** Use `crypto.getRandomValues()` for security-sensitive randomness and implement a `safeError` utility to mask internal errors from end-users.
