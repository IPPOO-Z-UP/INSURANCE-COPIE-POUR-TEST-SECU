## 2026-05-25 - Secure Randomness for Phone OTP and Agent Matricule Generation

**Vulnerability:**
The backend used `Math.random()` to generate sensitive strings, specifically 6-digit phone verification OTP codes and agent matricule identifiers (`IPPOO-A-XXXX`). Because `Math.random()` is PRNG-based and predictable, attackers could potentially predict generated OTP codes or matricule IDs.

**Learning:**
Standard JavaScript `Math.random()` is not cryptographically secure. In security-sensitive backend flows like OTP generation or user/agent ID assignment, predictable randomness creates brute-force or prediction vulnerabilities.

**Prevention:**
Always use Web Crypto API (`crypto.getRandomValues()`) or dedicated helper functions (e.g., `secureRandomInt` and `secureRandomSuffix`) when generating OTPs, passwords, session tokens, or unique resource identifiers.
