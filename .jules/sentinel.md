## 2026-02-28 - Replace Insecure Math.random() in Backend Flows

**Vulnerability:** Weak pseudo-random number generation via `Math.random()` used for critical backend security operations including phone OTP generation, agent matricule assignment, demo password creation, and internal transactional ID generation.
**Learning:** `Math.random()` is not cryptographically secure and yields predictable outputs under sequence analysis, which exposes SMS verification codes (OTP) and seed passwords to brute-force or prediction attacks.
**Prevention:** Use standard Web Crypto API (`crypto.getRandomValues`) with rejection sampling to eliminate modulo bias for integer range calculations (`secureRandomInt`) and alphanumeric suffix generation (`secureRandomSuffix`).
