# A-BOM (Adaptive Bill of Materials) — Design

**Status**: draft · 2026-05-13
**Owner**: CyberArmor platform
**Implementation phase**: 0 (design) → 1 (endpoint-agent collector) → 2+ (additional collectors)

## 1. Goal

A continuously-updated, tenant-scoped inventory of every software and hardware
component that touches the tenant's stack — endpoints, runtime services, source
repos, build artifacts, cloud resources, AI models. Each component is a
CycloneDX entry with provenance tracking which collector saw it and when.

Three things the A-BOM has to make possible day one:

1. **Vulnerability response**: "Who has log4j 2.14.x?" answers in seconds, not
   days, with a list of agent_ids / hosts / repos / cloud resources.
2. **Compliance evidence**: signed SBOM/HBOM export per tenant on demand, with
   the same provenance chain used internally — drops straight into a SOC 2 /
   FedRAMP / NIST AI RMF evidence pack.
3. **Drift detection**: today's component set vs yesterday's, with the
   policy-decision-style banner on what changed and where.

Non-goal v1: replacing dedicated build-time SBOM tools (Syft, Trivy,
CycloneDX-Maven, etc.). We *consume* their output where present and *generate*
where they're absent, but the canonical SBOM-producing process for a given
artifact can still live in CI.

## 2. Canonical format: CycloneDX 1.6

Why CycloneDX over SPDX or a custom shape:

- **Component.type covers H + S + ML + crypto + SaaS in one schema**:
  `application`, `framework`, `library`, `container`, `platform`,
  `operating-system`, `device`, `device-driver`, `firmware`, `file`,
  `machine-learning-model`, `data`, `cryptographic-asset`. SPDX 3.0 catches up
  partially but the tooling ecosystem is thinner.
- **Native provenance** (`properties`, `evidence`, `tools` blocks) means we can
  stamp "saw this via endpoint-agent rev abc123 at T" on every component
  without inventing custom keys.
- **Streamable BOV (Bill of Vulnerabilities)** + VEX support so the same
  document carries known-affected and known-not-affected state.
- **Existing customer tooling consumes it** — Dependency-Track, GitHub
  Dependency Graph, Anchore, Snyk, JFrog Xray all speak CycloneDX.

We treat the **on-disk format as canonical** but the **internal store as
normalized rows** keyed for fast query (see §5).

## 3. Data model

### 3.1 Component identity

The hardest problem. A `requests` library can appear from 4 collectors with 4
different shapes. Identity is computed as a stable hash over an ordered tuple:

```
identity_key = sha256(
  type || ":" ||                                          # cycloneDx component.type
  (purl || cpe || (name + "@" + version)) || ":" ||       # primary identifier
  (manufacturer || vendor || "") || ":" ||                # disambiguation
  (file_hash_sha256 || "")                                # extra precision when known
)
```

PURL (Package URL) is the preferred identifier; falls back to CPE for
hardware/OS; falls back to name@version + manufacturer when neither exists.
Sources collide deliberately — two collectors reporting the same component
share `identity_key` and we union their evidence.

### 3.2 Tenant-scoped row shape (storage)

```python
class ABOMComponent(Base):
    __tablename__ = "abom_components"
    id                = Column(String, primary_key=True)            # uuid
    tenant_id         = Column(String, nullable=False, index=True)
    identity_key      = Column(String, nullable=False, index=True)  # see §3.1
    type              = Column(String, nullable=False)              # cycloneDx type
    name              = Column(String, nullable=False)
    version           = Column(String, nullable=True)
    purl              = Column(String, nullable=True, index=True)
    cpe               = Column(String, nullable=True, index=True)
    manufacturer      = Column(String, nullable=True)
    licenses          = Column(JSONB, nullable=True)                # list[str]
    hashes            = Column(JSONB, nullable=True)                # {alg: digest}
    properties        = Column(JSONB, nullable=True)                # cycloneDx properties
    first_seen_at     = Column(DateTime(tz=True), nullable=False)
    last_seen_at      = Column(DateTime(tz=True), nullable=False)
    UniqueConstraint("tenant_id", "identity_key")
```

```python
class ABOMObservation(Base):
    """One sighting of a component by a collector at a point in time.
    Multiple observations roll up to one ABOMComponent via identity_key.
    Observations carry the *where* — which agent, repo, cloud resource.
    """
    __tablename__ = "abom_observations"
    id              = Column(String, primary_key=True)
    tenant_id       = Column(String, nullable=False, index=True)
    component_id    = Column(String, ForeignKey("abom_components.id"), index=True)
    collector       = Column(String, nullable=False)        # "endpoint-agent" | "rasp" | "ide" | "github" | "cloud-aws" | ...
    collector_version = Column(String, nullable=True)
    source_id       = Column(String, nullable=False)        # agent_id | repo_id | cloud_arn | ...
    source_kind     = Column(String, nullable=False)        # "agent" | "repo" | "container" | "cloud_resource" | "ide_workspace"
    hostname        = Column(String, nullable=True)
    path            = Column(String, nullable=True)         # install path, file path, ...
    observed_at     = Column(DateTime(tz=True), nullable=False)
    raw_properties  = Column(JSONB, nullable=True)          # whatever the collector emitted, preserved
```

Why two tables instead of one normalized BOM-per-source: we want fast queries
across observations ("every endpoint with this CVE"), and we want one
component to roll up evidence from multiple collectors without storing the
same row N times. The observation table is the event-sourced history; the
component table is the always-current rollup.

### 3.3 Export shape

Generated CycloneDX 1.6 document per tenant or per source. `components[]`
flattens the component rows; `properties` carries our provenance:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "2026-05-13T00:00:00Z",
    "tools": [{"vendor": "CyberArmor", "name": "abom-exporter", "version": "1.0"}],
    "component": {"type": "platform", "name": "tenant:{tenant_id}"}
  },
  "components": [
    {
      "type": "library",
      "name": "log4j-core",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "hashes": [{"alg": "SHA-256", "content": "..."}],
      "properties": [
        {"name": "cyberarmor:first_seen_at", "value": "2026-05-01T..."},
        {"name": "cyberarmor:observation_count", "value": "47"},
        {"name": "cyberarmor:collectors", "value": "endpoint-agent,rasp"}
      ],
      "evidence": {
        "occurrences": [
          {"location": "agent:0d1f7b99/usr/local/app/log4j-core-2.14.1.jar"},
          {"location": "agent:4167dc58/opt/services/log4j-core-2.14.1.jar"}
        ]
      }
    }
  ]
}
```

## 4. Collectors

Every collector implements one contract: emit a list of CycloneDX components
(or full BOM) with a `source_id` and `source_kind`. The control-plane handles
the rest (identity resolution, dedup, persistence).

| # | Collector              | Source                      | Mechanism                                     | Phase |
|---|------------------------|-----------------------------|-----------------------------------------------|-------|
| 1 | Endpoint agent (Linux/macOS) | Installed packages, binaries, OS, hardware | dpkg/rpm + sysctl + lspci/system_profiler   | 1     |
| 2 | Endpoint agent (Windows) | MSI / appx + WMI + DriverStore | wmic + Get-WindowsDriver + Get-AppxPackage    | 1     |
| 3 | Kernel-mode driver     | Loaded modules / drivers    | /sys/module + kldstat + driver enumeration    | 2     |
| 4 | RASP agent             | Process-loaded libs + runtime versions | /proc/{pid}/maps + JVM/.NET introspection    | 2     |
| 5 | IDE plugin (VS Code / JetBrains) | Workspace deps + extensions | manifest scan + extension list                | 3     |
| 6 | GitHub / GitLab / Azure Repos worker | Repo-resident SBOMs + dep manifests | API poll for SBOM + repo content scan         | 3     |
| 7 | Artifact repo (JFrog / Nexus / ECR / GHCR) | Container images, package indexes | API listing + manifest digest extraction     | 4     |
| 8 | Cloud inventory (AWS / GCP / Azure) | Compute, IAM, services      | AWS Config / Resource Graph / Asset Inventory | 4     |

Each collector goes through one ingest endpoint:

```
POST /agent/abom/ingest
POST /customer/abom/ingest   (when authenticated as a tenant user)
```

Body: `{source_id, source_kind, collector, collector_version, observed_at, components: CycloneDX-or-list}`

### 4.1 Endpoint-agent collector (phase 1)

What it collects:

- **Hardware**: CPU model/microcode/cores, RAM, disks, NICs (mac/model), TPM,
  GPU. `component.type = device | device-driver | firmware`.
- **OS**: distro, kernel version, image build. `type = operating-system`.
- **Installed packages**: dpkg / rpm / Homebrew / launchctl items / Windows MSI.
  `type = library | application`.
- **Loose binaries**: anything in `/usr/local/bin`, `/opt/*/bin`,
  `~/Applications` not owned by a package manager. Hash + heuristic name.
  `type = file | application`.
- **Browser extensions** (Chrome / Edge / Brave / Firefox / Safari profiles).
  `type = application` with `properties.cyberarmor:browser`.
- **AI-relevant**: Ollama-installed models, Hugging Face cache, .gguf files.
  `type = machine-learning-model`.

Cadence: full sweep at agent start, then delta sweeps every 6h. Hardware
re-emitted on boot/heartbeat (changes rarely). Sends compressed CycloneDX
to `/agent/abom/ingest` with `source_kind = "agent"`, `source_id = agent_id`.

Performance ceiling: 50k components on a heavy developer machine. The agent
streams in batches of 500, never holding the full set in memory.

### 4.2 RASP / runtime collector

Picks up what the endpoint agent can't see — actually-loaded libraries vs
installed-but-unused. Reads `/proc/{pid}/maps` per monitored process, plus
runtime-specific introspection (JVM MBean for jars, .NET appdomain, Python
sys.modules sampling). One `source_id` per workload, not per agent.

### 4.3 Source-control workers

A new service (or expanded `integration-control`) polls connected providers.
Per-repo job:

1. Check if repo emits SBOM artifacts (CI uploads CycloneDX/SPDX). Consume.
2. Otherwise scan manifest files (`package.json`, `requirements.txt`,
   `pom.xml`, `Cargo.toml`, `go.mod`, …) and generate a SBOM.
3. Emit one observation set per repo + branch + commit.

`source_id = "github:org/repo@branch"` so the same library appearing in app
code at commit X and infrastructure code at commit Y stays distinguishable.

### 4.4 Cloud inventory

AWS Config aggregator → JSON → CycloneDX `device` + `platform` components for
EC2/EKS/Lambda; `data` components for S3 buckets / RDS instances tagged with
classification. Same approach for GCP Asset Inventory and Azure Resource
Graph. Out of scope v1: deep introspection of what's *in* the resources.

## 5. Control-plane shape

New service or new module of control-plane — TBD. v1: module of control-plane
to leverage existing tenant scoping, auth, audit.

Endpoints:

```
POST   /agent/abom/ingest                         # collector → server
GET    /customer/abom/components                  # list, paginated, filterable
GET    /customer/abom/components/{id}             # single component + observations
GET    /customer/abom/components/{id}/sources     # which agents/repos/clouds have it
GET    /customer/abom/observations                # raw observation feed
GET    /customer/abom/export?format=cyclonedx     # CycloneDX 1.6 doc (signed)
GET    /customer/abom/export?format=spdx          # SPDX fallback for legacy consumers
GET    /customer/abom/search?q=log4j&version=^2   # cross-source search
GET    /customer/abom/drift?since=2026-05-12      # what changed
GET    /customer/abom/coverage                    # which sources have reported recently
POST   /customer/abom/vex                         # admin marks "not affected"
```

Filters on `/components`: type, manufacturer, has_cve, license, source_kind,
collector, age. Same pager helper recent views use.

### 5.1 Persistence + lifecycle

- Components are upserted on observation ingest, identity-key keyed.
- Observations are append-only; index `(tenant_id, component_id, observed_at)`.
- Component `last_seen_at` updates from newest observation timestamp.
- Drift: component "disappears" if no observation in N days (default 7); we
  keep the row but mark it `last_seen_at` old. Operators see this as
  "removed" in the drift view.

### 5.2 CVE / VEX overlay

We don't ship a CVE database in v1, but the model accommodates it: a
`/customer/abom/vex` endpoint lets admins import VEX, and the export embeds
the BOV layer. CVE matching against components is a Phase-5 follow-up that
plugs into NVD / OSV / GitHub Advisory feeds.

## 6. Portal surface

New nav entry **"Bill of Materials"** under DLP/Upload Discovery cluster
since it's most operationally similar (inventory + drift + evidence). Three
sub-views:

1. **Components**: paginated table; filter by type / source / license; click
   row → detail panel with observations and provenance.
2. **Drift**: what was added / removed / version-changed since X. Same
   time-window picker pattern as Compliance / Action Graph.
3. **Coverage**: per-collector freshness chart — when did each source last
   report, how many components per source. Helps the operator see when a
   collector silently stops.
4. **Export**: button generates a signed CycloneDX (and SPDX) per tenant on
   demand; same surface as the evidence-export action on Reports.

Mission Control gets one new tile: "A-BOM components" with delta-since-
yesterday.

## 7. Phasing

| Phase | Scope                                                                  | Demo value                                                |
|-------|------------------------------------------------------------------------|-----------------------------------------------------------|
| 0     | This doc, schema migrations, ingest endpoint stub                     | Architectural sign-off                                    |
| 1     | Endpoint-agent collector (Linux/macOS first, Windows next) + portal Components view + CycloneDX export | "Here's our Mac's installed software + hardware in seconds; click 'Export' and you get a signed CycloneDX doc." |
| 2     | RASP runtime collector + Drift view                                   | "RASP confirms log4j-core is actually loaded in PID 4231, not just installed." |
| 3     | IDE plugin (VS Code first) + GitHub/GitLab worker                     | "Same component appears from endpoint, repo, and IDE workspace — we see it across the SDLC." |
| 4     | Artifact-repo + cloud-inventory collectors                            | "We see the container in JFrog, the same container running in EKS, and the same agent watching it." |
| 5     | CVE / OSV / GHSA overlay + VEX management + Drift policy hooks        | "log4j 2.14.1 + CVE-2021-44228 → policy 'block_upload_on_vulnerable_dep' fires."  |

Each phase ships a usable demo.

## 8. Open questions

1. **Storage backend**: SQLAlchemy + JSONB scales to ~10M observations
   per-tenant; past that we want time-series partitioning. Punting until
   real numbers; ship phase 1 on the existing Postgres.
2. **Signing**: CycloneDX export should be CMS or in-toto signed (existing
   audit-log signing infra). Pick one before phase 1 ships.
3. **PURL coverage for AI models**: Hugging Face has a `pkg:huggingface/...`
   PURL spec proposal but it's not finalized; we'll use it provisionally
   and adjust if the spec lands differently.
4. **Hardware identity for ephemeral workloads** (containers, lambdas):
   `manufacturer = "aws"` / `cloud_resource_arn` as the dedup key, since
   serial numbers don't apply.
5. **Telemetry overlap with current /telemetry/ingest**: A-BOM ingest is
   high-volume but rare; keep it on its own endpoint so it doesn't crowd
   the existing realtime path.

## 9. What's next

Phase 1 implementation, in order:

1. **DB migration** — `abom_components` and `abom_observations` tables.
2. **Ingest endpoint** — `POST /agent/abom/ingest` with the auth flow the
   agent already uses; idempotent on identity_key.
3. **Endpoint-agent collector module** — `agents/endpoint-agent/collectors/abom.py`,
   wired into the existing periodic-task runner.
4. **CycloneDX exporter** — `services/control-plane/abom_export.py`.
5. **Portal components view** — `customer-portal/app.js` viewBillOfMaterials.
6. **Wire into Mission Control** — single tile.

Ready to start on phase 1 when this doc is approved.
