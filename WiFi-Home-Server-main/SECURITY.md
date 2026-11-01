# Security Policy

## Implemented Controls

- The server binds to all interfaces on port `8765` by default and uses HTTPS with a self-signed certificate.
- At server start, the host operator sets a password of at least 12 characters. It is not written to disk; PBKDF2-HMAC-SHA256 derives an in-memory verifier and AES key material.
- Clients authenticate with a one-time challenge. Shared file bytes are encrypted with AES-256-GCM before transmission and decrypted in the browser.
- The browser compares the SHA-256 digest of the decrypted file with the host's digest before saving it.
- Paths are resolved and checked against the selected shared root. Symlinks escaping that root are excluded.

## Important Limitations

- The generated certificate is self-signed. Install and trust `server-cert.pem` on every client, and verify the SHA-256 fingerprint through a separate trusted channel. Do not ignore certificate warnings without verification.
- Passwords should be unique and strong. The challenge proof can be captured by an attacker with network visibility and allows offline password guessing; HTTPS protects it only when clients correctly trust the host certificate.
- AES-GCM transfers are currently limited to files up to 256 MiB because encryption and browser decryption buffer each file in memory.
- This application shares downloads only. It has no upload/receive endpoint, account database, or password reset feature.
- The application has not been independently audited. Use trusted WLANs and share only selected folders/files.

## Reporting a Vulnerability

Please report security issues privately through the repository's GitHub security reporting feature. Include impact, reproduction steps, and any suggested mitigation.

## Reporting a Vulnerability

If you discover a security vulnerability in WiFi Home Server, please do not disclose it publicly by creating a GitHub issue right away. 

Instead, please send an email directly to the project maintainers or use the private vulnerability reporting feature on GitHub.

We will try to review your report within 48-72 hours. Please provide full details:
- A description of the vulnerability and its impact.
- Steps to reproduce the issue.
- Any suggested mitigations.

We appreciate all efforts to make our project more secure!
