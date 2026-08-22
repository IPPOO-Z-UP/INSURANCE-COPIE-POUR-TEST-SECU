# Sentinel Security Journal

## 2026-08-22 - Predictable PRNG in OTP and Sensitive Identifier Generation
**Vulnerability:** Use of `Math.random()` in `Backend API/functions/server/index.tsx` for generating SMS OTP verification codes, agent matricules, demo account passwords, and internal entity IDs.
**Learning:** Standard JavaScript `Math.random()` is PRNG-based (e.g., xorshift128+) and predictable. Attackers capable of observing generated sequences or timing can predict future OTPs or session identifiers.
**Prevention:** Always use Web Crypto API (`crypto.getRandomValues`) wrapped in a rejection sampling implementation (`secureRandomInt` and `secureRandomSuffix`) to ensure cryptographically secure randomness without modulo bias.
