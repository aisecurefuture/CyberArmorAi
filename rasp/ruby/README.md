# CyberArmor Ruby RASP

Ruby Runtime Application Self-Protection package for inspecting AI-bound traffic, detecting prompt injection, and enforcing DLP-aware policy controls.

For shared bootstrap enrollment guidance, common environment variables, and the install-scoped credential flow, see [Client Bootstrap Setup](/Users/patrickkelly/Documents/CyberArmorAi/docs/architecture/client-bootstrap-setup.md).

## Package

- Primary source: [cyberarmor_rasp_impl.rb](/Users/patrickkelly/Documents/CyberArmorAi/rasp/ruby/cyberarmor_rasp_impl.rb)

## Local Verification

```bash
cd /Users/patrickkelly/Documents/CyberArmorAi
ruby -c rasp/ruby/cyberarmor_rasp_impl.rb
```

## Bootstrap Notes

- Preferred control plane variable: `CYBERARMOR_CONTROL_PLANE_URL`
- Preferred bootstrap variable: `CYBERARMOR_BOOTSTRAP_TOKEN`
- Preferred tenant variable: `CYBERARMOR_TENANT_ID`

Preferred operational flow is to redeem a one-time bootstrap token into an install-scoped credential during configuration setup.
