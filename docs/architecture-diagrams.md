# Architecture and workflow diagrams

Mermaid diagrams for the Docker Container Scanner. Render in any Markdown viewer that supports Mermaid (e.g. GitHub, GitLab, VS Code).

---

## Architecture diagram

High-level components and how they connect.

```mermaid
flowchart TB
  subgraph inputs [Inputs]
    ImageRef[Image ref]
    Dockerfile[Dockerfile path]
  end

  subgraph cli [CLI]
    Flags[Flags and config]
    Flags --> CLI_Orchestrator[CLI orchestrator]
  end

  subgraph engine [Scanner engine]
    TrivyImage[Trivy image]
    TrivyConfig[Trivy config]
    TrivyImage --> RawFindings[Raw findings]
    TrivyConfig --> RawFindings
  end

  subgraph pipeline [Pipeline]
    Enricher[Remediation enricher]
    ReportGen[Report generator]
    RawFindings --> Enricher
    Enricher --> EnrichedFindings[Enriched findings]
    EnrichedFindings --> ReportGen
  end

  subgraph outputs [Outputs]
    SARIF[SARIF]
    Markdown[Markdown]
    HTML[HTML]
    ReportGen --> SARIF
    ReportGen --> Markdown
    ReportGen --> HTML
  end

  subgraph policy [Policy]
    FailOn[Fail-on check]
    EnrichedFindings --> FailOn
    FailOn --> ExitCode[Exit code 0 or 1]
  end

  ImageRef --> CLI_Orchestrator
  Dockerfile --> CLI_Orchestrator
  CLI_Orchestrator --> TrivyImage
  CLI_Orchestrator --> TrivyConfig
  CLI_Orchestrator --> Enricher
  CLI_Orchestrator --> ReportGen
  CLI_Orchestrator --> FailOn
```

---

## Scan workflow diagram

End-to-end flow from user command to report and exit code.

```mermaid
sequenceDiagram
  participant User
  participant CLI
  participant TrivyImage as Trivy image
  participant TrivyConfig as Trivy config
  participant Enricher
  participant Report
  participant Policy

  User->>CLI: scan --image X [--dockerfile D]
  CLI->>TrivyImage: trivy image --format json X
  TrivyImage-->>CLI: JSON vulnerabilities

  alt Dockerfile set
    CLI->>TrivyConfig: trivy config --format json dir(D)
    TrivyConfig-->>CLI: JSON misconfigurations
  end

  CLI->>CLI: Merge findings
  CLI->>Enricher: Enrich findings
  Enricher-->>CLI: Enriched findings

  CLI->>Report: Generate SARIF, Markdown, HTML
  Report-->>CLI: Files written

  CLI->>Policy: Evaluate fail-on
  alt Policy violated
    Policy-->>CLI: fail, reason
    CLI->>User: Exit 1, stderr reason
  else Policy OK
    Policy-->>CLI: pass
    CLI->>User: Exit 0, report path
  end
```

---

## Data flow (simplified)

```mermaid
flowchart LR
  A[Image ref] --> B[Trivy image]
  C[Dockerfile path] --> D[Trivy config]
  B --> E[Raw findings]
  D --> E
  E --> F[Enricher]
  F --> G[Enriched findings]
  G --> H[Report generator]
  H --> I[SARIF]
  H --> J[Markdown]
  H --> K[HTML]
  G --> L[Fail-on policy]
  L --> M[Exit 0 or 1]
```

---

## Deployment topologies

```mermaid
flowchart TB
  subgraph topo1 [CLI-only]
    C1[CI runner]
    C1 --> S1[scanner binary]
    S1 --> T1[Trivy]
    S1 --> O1[Reports on disk]
  end

  subgraph topo2 [Docker image]
    C2[CI or host]
    C2 --> D2[scanner image]
    D2 --> T2[Trivy inside image]
    D2 --> O2[Reports in volume]
  end

  subgraph topo3 [Server and UI later]
    C3[Browser]
    C3 --> W3[Web UI]
    W3 --> SRV[scanner serve]
    SRV --> T3[Trivy]
    SRV --> O3[Report JSON or file]
  end
```

---

*See [System design](system-design.md) for detailed components, interfaces, and failure modes.*
