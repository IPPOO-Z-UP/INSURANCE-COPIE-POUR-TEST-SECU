# Sentinel Security Journal

## 2026-06-12 - Prevent TOTP Secret Leak to Third-Party QR Code Generator
**Vulnerability:** The agent profile page (AgentProfilePage.tsx) was generating QR codes for Two-Factor Authentication setup using an external, third-party service (api.qrserver.com) by passing the sensitive `otpauth://` URI (which includes the TOTP secret key, agent email, and issuer) as a URL parameter. This leaked the agent's multi-factor authentication secrets to an external server.
**Learning:** The external QR code generation was implemented as a quick convenience. However, any external service used to generate QR codes for sensitive credentials receives the plaintext secret, allowing them (or anyone intercepting the requests) to generate the TOTP codes and bypass 2FA.
**Prevention:** Always generate MFA QR codes locally inside the client's browser (e.g., using `qrcode.react` to render SVG elements) so that the TOTP secret key never leaves the user's device.
