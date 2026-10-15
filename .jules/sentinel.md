## 2026-05-30 - Cryptographically Secure OTP Generation
**Vulnerability:** Use of `Math.random()` in `/phone/otp/send` for generating 6-digit phone verification OTPs, which is pseudo-random and predictable via state estimation algorithms (e.g. V8 engine PRNG state recovery).
**Learning:** `Math.random()` should never be used for security-sensitive tokens, OTPs, password generation, or secret identifiers because its output can be forecasted given sufficient observations.
**Prevention:** Always use cryptographically secure random number generators (`crypto.getRandomValues()`) when generating authentication tokens, OTPs, secrets, or security identifiers.
