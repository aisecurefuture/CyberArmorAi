# CyberArmor .NET RASP

.NET Runtime Application Self-Protection package for inspecting AI-bound traffic, detecting prompt injection, and enforcing DLP-aware policy controls.

For shared bootstrap enrollment guidance, common environment variables, and the install-scoped credential flow, see [Client Bootstrap Setup](/Users/patrickkelly/Documents/CyberArmorAi/docs/architecture/client-bootstrap-setup.md).

## Package

- Project file: [CyberArmorRasp.csproj](/Users/patrickkelly/Documents/CyberArmorAi/rasp/dotnet/CyberArmorRasp.csproj)
- Middleware source: [CyberArmorRaspMiddleware.cs](/Users/patrickkelly/Documents/CyberArmorAi/rasp/dotnet/CyberArmorRaspMiddleware.cs)

## Local Verification

```bash
cd /Users/patrickkelly/Documents/CyberArmorAi
dotnet build rasp/dotnet/CyberArmorRasp.csproj
```

## Bootstrap Notes

- Preferred control plane variable: `CYBERARMOR_CONTROL_PLANE_URL`
- Preferred bootstrap variable: `CYBERARMOR_BOOTSTRAP_TOKEN`
- Preferred tenant variable: `CYBERARMOR_TENANT_ID`

Preferred operational flow is to redeem a one-time bootstrap token into an install-scoped credential before ongoing middleware and outbound handler activity.
