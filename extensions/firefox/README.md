# CyberArmor Firefox Extension

Firefox browser extension for AI activity monitoring, DLP checks, phishing protection, and policy enforcement.

For shared bootstrap enrollment guidance, common environment variables, and the install-scoped credential flow, see [Client Bootstrap Setup](/Users/patrickkelly/Documents/CyberArmorAi/docs/architecture/client-bootstrap-setup.md).

## Package

- Firefox extension id: `cyberarmor@cyberarmor.ai`
- Manifest: [manifest.json](/Users/patrickkelly/Documents/CyberArmorAi/extensions/firefox/manifest.json)
- Options UI: [options.html](/Users/patrickkelly/Documents/CyberArmorAi/extensions/firefox/options.html)

## Local Development

Load the folder as a temporary add-on in Firefox during local testing.

## Bootstrap Notes

Bootstrap enrollment is exposed through the options UI and background startup flow.

- one-time bootstrap token
- control plane URL
- optional tenant identifier
- redeemed install-scoped credential stored in extension state

Preferred operational flow is to enroll once with a short-lived bootstrap token and avoid embedding any tenant-wide secret in the packaged extension.
