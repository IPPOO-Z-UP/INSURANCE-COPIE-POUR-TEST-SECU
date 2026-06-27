## 2025-05-22 - [Fixed TOTP secret leak to external QR service]
**Vulnerability:** Sending TOTP `otpauth://` URIs (containing the shared secret) to an external QR code generation API (`api.qrserver.com`) via a simple `<img>` tag.
**Learning:** Even though it's "just a QR code", sending the raw `otpauth` URI to a third party exposes the secret to their logs and infrastructure, compromising the 2FA security.
**Prevention:** Always generate security-sensitive QR codes (like TOTP secrets) client-side using a trusted library (e.g., `qrcode.react`).
