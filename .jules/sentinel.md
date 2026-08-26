## 2026-05-25 - Replace Predictable Math.random with Web Crypto Alternatives

**Vulnerability:** Predictable PRNG `Math.random()` was used in backend API endpoints for generating SMS OTP verification codes, agent matricule numbers, demo passwords, and entity ID suffixes.

**Learning:** `Math.random()` lacks cryptographic entropy, allowing attackers to potentially predict OTP values or generated passwords. Standard Web Crypto `crypto.getRandomValues()` combined with rejection sampling must be used to ensure uniform, cryptographically secure values without modulo bias.

**Prevention:** Always use `secureRandomInt(min, max)` and `secureRandomSuffix(length)` backed by `crypto.getRandomValues()` for any backend OTP, credential, token, or identifier generation.
