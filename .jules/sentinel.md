## 2026-04-10 - Insecure PRNG in Authentication OTP & Identity Generation

**Vulnerability:** The phone OTP verification endpoint (`/phone/otp/send`) generated 6-digit one-time passcodes using JavaScript's built-in `Math.random()`. `Math.random()` relies on pseudo-random generators (such as XorShift128+) whose internal state can be reconstructed by observing consecutive outputs, enabling attackers to predict future OTP codes and bypass authentication or hijack phone verification. A similar insecure generation pattern was present in agent matricule generation (`resolveAgentMatricule`).

**Learning:** When developing rapid prototypes or utility endpoints, developers frequently default to `Math.random()` for numeric codes. In security-sensitive flows (OTPs, session tokens, identity numbers), PRNG sequences introduce high exploitability.

**Prevention:** Always use Web Crypto API (`crypto.getRandomValues`) with uniform rejection sampling (`secureRandomInt(min, max)`) or `crypto.randomUUID()` when generating tokens, verification codes, and security identifiers. Never use `Math.random()` in authentication or authorization pathways.
