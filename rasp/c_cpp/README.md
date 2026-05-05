# CyberArmor C/C++ RASP

C and C++ Runtime Application Self-Protection package for inspecting AI-bound traffic, detecting prompt injection, and enforcing DLP-aware policy controls.

For shared bootstrap enrollment guidance, common environment variables, and the install-scoped credential flow, see [Client Bootstrap Setup](/Users/patrickkelly/Documents/CyberArmorAi/docs/architecture/client-bootstrap-setup.md).

## Package

- Build file: [CMakeLists.txt](/Users/patrickkelly/Documents/CyberArmorAi/rasp/c_cpp/CMakeLists.txt)
- Public header: [cyberarmor_rasp.h](/Users/patrickkelly/Documents/CyberArmorAi/rasp/c_cpp/include/cyberarmor_rasp.h)
- Primary source: [cyberarmor_rasp.c](/Users/patrickkelly/Documents/CyberArmorAi/rasp/c_cpp/src/cyberarmor_rasp.c)

## Local Verification

```bash
cd /Users/patrickkelly/Documents/CyberArmorAi
cc -std=c11 -shared -fPIC -I rasp/c_cpp/include rasp/c_cpp/src/cyberarmor_rasp.c -o /private/tmp/libcyberarmor_rasp.dylib -ldl -lpthread
```

## Bootstrap Notes

- Preferred control plane variable: `CYBERARMOR_CONTROL_PLANE_URL`
- Preferred bootstrap variable: `CYBERARMOR_BOOTSTRAP_TOKEN`
- Preferred tenant variable: `CYBERARMOR_TENANT_ID`
- Optional runtime label: `CYBERARMOR_RASP_SUBJECT_NAME`

Preferred operational flow is to redeem a one-time bootstrap token into an install-scoped credential during initialization.
