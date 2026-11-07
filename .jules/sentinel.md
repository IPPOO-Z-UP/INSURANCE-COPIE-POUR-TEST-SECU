## 2026-05-30 - Constant-time comparison for webhook secrets and cron tokens

**Vulnerability:** Payment webhook endpoints (KkiaPay, CinetPay, FedaPay, MTN MoMo) and cron maintenance endpoints were validating secrets and signatures using non-constant-time equality operators (`!==` / `===`). This allows attackers to perform timing side-channel attacks by measuring minute latency differences to deduce secrets byte by byte.

**Learning:** In Deno EdgeRuntime and browser environments, Node's `crypto.timingSafeEqual` is not natively available or requires variable-length padding hacks. Direct string comparison short-circuits on the first mismatched character, creating measurable timing discrepancies.

**Prevention:** Normalize secrets to fixed-length 32-byte buffers by hashing both sides with SHA-256 before performing a bitwise XOR reduction loop (`safeCompareSecret`). Always compare authentication tokens and cryptographic signatures in constant time.
