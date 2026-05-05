# CyberArmor Chromium-Based Browser Extension

Shared browser extension package for Chromium-based targets such as Edge and Chrome, providing AI activity monitoring, DLP checks, phishing protection, and policy enforcement.

For shared bootstrap enrollment guidance, common environment variables, and the install-scoped credential flow, see [Client Bootstrap Setup](/Users/patrickkelly/Documents/CyberArmorAi/docs/architecture/client-bootstrap-setup.md).

## Package

- Shared package name: `cyberarmor-browser-shared`
- Manifest: [manifest.json](/Users/patrickkelly/Documents/CyberArmorAi/extensions/chromium-shared/manifest.json)
- Options UI: [options.html](/Users/patrickkelly/Documents/CyberArmorAi/extensions/chromium-shared/options.html)

## Local Development

```bash
cd /Users/patrickkelly/Documents/CyberArmorAi/extensions/chromium-shared
npm install
npm run build:pqc
```

Load the folder as an unpacked extension in the target Chromium-based browser during local testing.

## Bootstrap Notes

Bootstrap enrollment is exposed through the options UI and background startup flow.

- one-time bootstrap token
- control plane URL
- optional tenant identifier
- redeemed install-scoped credential stored in extension state

Preferred operational flow is to enroll once with a short-lived bootstrap token and avoid embedding any tenant-wide secret in the packaged extension.
