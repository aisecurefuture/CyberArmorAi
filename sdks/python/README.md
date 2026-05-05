# CyberArmor Python SDK

Python client library for integrating CyberArmor policy, identity, and AI security controls into server-side Python applications.

For shared bootstrap enrollment guidance, common environment variables, and the install-scoped credential flow, see [Client Bootstrap Setup](/Users/patrickkelly/Documents/CyberArmorAi/docs/architecture/client-bootstrap-setup.md).

## Package

- Package name: `cyberarmor-sdk`
- Python requirement: `>=3.9`

## Local Development

```bash
cd /Users/patrickkelly/Documents/CyberArmorAi/sdks/python
python3 -m pip install -e .
```

## Bootstrap Notes

- Preferred control plane variable: `CYBERARMOR_CONTROL_PLANE_URL`
- Preferred bootstrap variable: `CYBERARMOR_BOOTSTRAP_TOKEN`
- Preferred tenant variable: `CYBERARMOR_TENANT_ID`

The SDK can redeem a one-time bootstrap token into an install-scoped credential during configuration loading.
