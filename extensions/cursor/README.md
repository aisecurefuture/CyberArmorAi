# CyberArmor Cursor Extension

Cursor extension for monitoring AI-assisted coding activity, applying DLP checks, and enforcing CyberArmor policy controls inside the editor.

For shared bootstrap enrollment guidance, common environment variables, and the install-scoped credential flow, see [Client Bootstrap Setup](/Users/patrickkelly/Documents/CyberArmorAi/docs/architecture/client-bootstrap-setup.md).

## Package

- Extension id: `cyberarmor-cursor`
- Main entrypoint: `out/extension.js`

## Local Development

```bash
cd /Users/patrickkelly/Documents/CyberArmorAi/extensions/cursor
npm install
npm run compile
```

## Bootstrap Notes

The extension supports bootstrap enrollment through its settings and command surface:

- `cyberarmor.controlPlaneUrl`
- `cyberarmor.bootstrapToken`
- `cyberarmor.apiKey`
- `cyberarmor.tenantId`
- command: `CyberArmor: Redeem Bootstrap Token`

Preferred operational flow is to provide a one-time bootstrap token and let the extension redeem it into an install-scoped credential.
