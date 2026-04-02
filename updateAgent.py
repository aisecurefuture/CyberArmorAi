sudo python3 - <<'PY'
import json
from pathlib import Path
p = Path("/etc/cyberarmor/agent.json")
cfg = json.loads(p.read_text())
cfg["control_plane_url"] = "http://localhost:8000"
p.write_text(json.dumps(cfg, indent=2))
print(f"updated {p}")
PY
