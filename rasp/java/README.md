# CyberArmor Java RASP

Java Runtime Application Self-Protection agent for inspecting AI-bound traffic, detecting prompt injection, and enforcing DLP-aware policy controls.

For shared bootstrap enrollment guidance, common environment variables, and the install-scoped credential flow, see [Client Bootstrap Setup](/Users/patrickkelly/Documents/CyberArmorAi/docs/architecture/client-bootstrap-setup.md).

## Package

- Maven project: [pom.xml](/Users/patrickkelly/Documents/CyberArmorAi/rasp/java/pom.xml)
- Primary agent source: [CyberArmorLegacyAgent.java](/Users/patrickkelly/Documents/CyberArmorAi/rasp/java/src/main/java/ai/cyberarmor/rasp/CyberArmorLegacyAgent.java)

## Local Verification

```bash
cd /Users/patrickkelly/Documents/CyberArmorAi/rasp/java
mvn -Dmaven.repo.local=/tmp/m2repo test
```

## Bootstrap Notes

- Preferred control plane variable: `CYBERARMOR_CONTROL_PLANE_URL`
- Preferred bootstrap variable: `CYBERARMOR_BOOTSTRAP_TOKEN`
- Optional agent identity: `CYBERARMOR_AGENT_ID`
- Optional runtime label: `CYBERARMOR_RASP_SUBJECT_NAME`

Preferred operational flow is to redeem a one-time bootstrap token into an install-scoped credential before normal policy sync and telemetry calls.
