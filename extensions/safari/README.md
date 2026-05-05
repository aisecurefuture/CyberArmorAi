# CyberArmor Safari Extension

Safari browser extension for AI activity monitoring, DLP checks, phishing protection, and policy enforcement.

For shared bootstrap enrollment guidance, common environment variables, and the install-scoped credential flow, see [Client Bootstrap Setup](/Users/patrickkelly/Documents/CyberArmorAi/docs/architecture/client-bootstrap-setup.md).

## Package

- Manifest: [manifest.json](/Users/patrickkelly/Documents/CyberArmorAi/extensions/safari/manifest.json)
- Safari metadata: [Info.plist](/Users/patrickkelly/Documents/CyberArmorAi/extensions/safari/Info.plist)

## Local Development

Load the extension through the Safari extension development workflow used by your local packaging setup.

## Bootstrap Notes

Bootstrap enrollment is handled by the extension runtime during setup/startup and should be configured with:

- control plane URL
- one-time bootstrap token
- optional tenant identifier

Preferred operational flow is to enroll once with a short-lived bootstrap token and persist only the redeemed install-scoped credential.
