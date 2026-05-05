# CyberArmor Microsoft 365 Add-in

Microsoft 365 add-in package for bringing CyberArmor policy and AI security controls into Office workflows.

For shared bootstrap enrollment guidance, common environment variables, and the install-scoped credential flow, see [Client Bootstrap Setup](/Users/patrickkelly/Documents/CyberArmorAi/docs/architecture/client-bootstrap-setup.md).

## Package

- Package name: `cyberarmor-office365`
- Manifest: [manifest.xml](/Users/patrickkelly/Documents/CyberArmorAi/extensions/office365/manifest.xml)

## Local Development

```bash
cd /Users/patrickkelly/Documents/CyberArmorAi/extensions/office365
npm install
npm run build
```

## Bootstrap Notes

The add-in handlers support bootstrap redemption during setup and should be configured with:

- control plane URL
- one-time bootstrap token
- optional tenant identifier

Preferred operational flow is to redeem the bootstrap token once and persist only the returned install-scoped credential.
