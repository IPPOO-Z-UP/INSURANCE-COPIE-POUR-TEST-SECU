# Sentinel Security Journal

## 2026-06-11 - Cryptographically Insecure Pseudo-Random OTP Generation
**Vulnerability:** The phone verification endpoint (`/phone/otp/send`) generated 6-digit one-time passwords using `Math.random()`. `Math.random()` in V8/Deno is not a cryptographically secure pseudo-random number generator (CSPRNG), making numeric OTPs vulnerable to PRNG state recovery and prediction.
**Learning:** In backend endpoints where authentication proof tokens or verification codes are issued, developers may casually use `Math.random()` for convenience, even when `crypto.getRandomValues` is already utilized elsewhere for HMAC secrets and TOTP secrets.
**Prevention:** Always use Web Crypto (`crypto.getRandomValues`) to produce random bytes for security credentials, authentication tokens, and OTP codes.
