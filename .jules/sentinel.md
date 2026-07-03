## 2025-05-14 - Insecure Randomness and Error Leakage
**Vulnerability:** Use of `Math.random()` for OTP generation and leaking raw error messages (interpolation of `${err}`) in HTTP responses.
**Learning:** The codebase lacked a central security utility for CSPRNG randomness and error sanitization, leading to insecure patterns in critical paths like Signup and OTP.
**Prevention:** Use `secureRandomInt` for all security-sensitive random values and `safeError` to mask internal details in production responses.
