# CyberArmor / CyberArmor Platform Architecture

## The platform in one view (Mermaid)

```mermaid
graph TD
  subgraph External["External Web"]
    W1[URLs / Web Content]
  end

  subgraph TrustGate["URL & Context Trust Gate (port 8014)"]
    G1[Canonicalise + Cache]
    G2[Safe Crawler]
    G3[Detonation Worker\nport 8015]
    G4[Heuristic + ML Scoring]
    G5[Policy Decision]
    G1 --> G2 --> G4
    G2 --> G3 --> G4
    G4 --> G5
  end

  subgraph Consumers
    E1[Endpoint Agent]
    E2[Browser Extension]
    E3[RASP Python/Go/Java/Node]
    E4[LangChain / LlamaIndex SDK]
  end

  subgraph Runtime
    R1[AISR Runtime API]
    R2[Detection Service]
    R3[Policy Service]
    R4[Response Orchestrator]
  end

  subgraph ControlPlane
    C1[Control Plane API]
    C2[(Postgres)]
    C3[Audit / Evidence]
    C4[Compliance Engine]
  end

  subgraph Telemetry
    T1[eBPF Sensor]
    T2[OTLP / JSON Ingest]
  end

  W1 --> G1
  Consumers --> G1
  G5 --> R2
  G5 --> R3
  G5 --> C3

  E1 --> R1
  E3 --> R1
  E4 --> R1
  T1 --> T2 --> C1

  R1 --> R2
  R1 --> R3
  R1 --> R4
  R1 --> C1
  C1 --> C2
  C1 --> C3
  C1 --> C4
```

## Product narrative (investor + buyer)
CyberArmor is an **AI Security Runtime** that enforces policy at the point where AI is actually used:
- before AI ingests external content (URL / Context Trust Gate)
- on the endpoint and inside the application
- on the network path
- and at the kernel (telemetry)

Unlike single-layer “prompt filters,” CyberArmor provides a **closed-loop runtime**:
1) gate external content before ingestion, 2) observe, 3) decide, 4) act, 5) prove.

## Key proof points
- **Pre-ingestion gate**: URL Trust Gate with ML-based detection, three reputation feeds, and Playwright detonation — running end-to-end, 15-minute PoC installer available
- **Linux**: eBPF sensor for process + network telemetry
- **macOS**: Endpoint Security framework sensor (pilot)
- **Windows**: kernel sensor (pilot)

## What to demo in 60 seconds
1. Run `scripts/poc/install.sh` — stack up in under 2 minutes
2. `python run_url_trust_gate_demo.py` submits four crafted attack pages
3. Each returns a live verdict (allow / warn / block) in under 120 ms
4. Audit service records the evidence chain with scores and IOCs
5. Policy service shows the tenant block-list rule that triggered the block
