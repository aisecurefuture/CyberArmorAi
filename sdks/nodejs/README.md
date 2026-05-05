# CyberArmor Node.js SDK

Node.js and TypeScript SDK for integrating CyberArmor policy, identity, and AI security controls into server-side JavaScript applications.

For shared bootstrap enrollment guidance, common environment variables, and the install-scoped credential flow, see [Client Bootstrap Setup](/Users/patrickkelly/Documents/CyberArmorAi/docs/architecture/client-bootstrap-setup.md).

## Package

- Package name: `@cyberarmor/sdk`
- Build output: `dist/cjs`, `dist/esm`, and generated types

## Local Development

```bash
cd /Users/patrickkelly/Documents/CyberArmorAi/sdks/nodejs
npm install
npm run build
```

## Bootstrap Notes

- Preferred control plane variable: `CYBERARMOR_CONTROL_PLANE_URL`
- Preferred bootstrap variable: `CYBERARMOR_BOOTSTRAP_TOKEN`
- Preferred tenant variable: `CYBERARMOR_TENANT_ID`

The SDK supports async bootstrap redemption so applications can exchange a one-time token for an install-scoped credential before normal API calls.
