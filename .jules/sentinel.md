## 2025-05-15 - Local QR Code Generation for TOTP
**Vulnerability:** 2FA (TOTP) secrets were being leaked to a third-party external service (`api.qrserver.com`) during QR code generation.
**Learning:** Using external APIs for generating QR codes containing sensitive data (like `otpauth` URIs) exposes those secrets to the third-party provider's logs and infrastructure.
**Prevention:** Always generate QR codes for sensitive data locally using client-side libraries like `qrcode.react`.
