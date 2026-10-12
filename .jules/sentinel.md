## 2026-03-30 - Cryptographically Secure OTP Generation
**Vulnerability:** Phone OTP generation in `Backend API/functions/server/index.tsx` used `Math.random()`, exposing OTP codes to potential prediction attacks.
**Learning:** In Edge/Supabase functions, `crypto.getRandomValues()` provides Web Crypto API cryptographically secure randomness for security tokens and OTPs.
**Prevention:** Always use `crypto.getRandomValues()` instead of `Math.random()` when generating security-sensitive values such as OTPs, authentication tokens, or passwords.
