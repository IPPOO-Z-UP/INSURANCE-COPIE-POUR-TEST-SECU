## 2026-05-25 - Replace Math.random() with Web Crypto CSPRNG in Backend API Flows

**Vulnerability:** Predictable PRNG (`Math.random()`) was used in backend API functions for generating critical security tokens, phone verification OTPs, agent matricules, payment/visit identifiers, audit IDs, and demo passwords. `Math.random()` in V8/Deno uses xorshift128+, which is not cryptographically secure and can allow attackers to predict upcoming OTPs or ID values.

**Learning:** Pseudo-random number generators like `Math.random()` are designed for speed, not unpredictability. In backend flows—especially authentication and OTP verification—using `Math.random()` exposes systems to brute-force or sequence prediction attacks. Additionally, simple modulo operations (`% range`) introduce modulo bias when mapped over large random integer spaces.

**Prevention:** Use `crypto.getRandomValues()` via `Web Crypto API` for all security-sensitive randomness. Use rejection sampling (as implemented in `secureRandomInt`) to eliminate modulo bias when generating integer ranges (such as 6-digit OTP codes and matricule numbers).
