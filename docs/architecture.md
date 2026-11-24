# Architecture

```mermaid
flowchart LR
    subgraph Sources
        AWS[AWS API or Moto]
        AZ[Azure fixtures or SDK]
        TF[Terraform plan JSON]
        EXT[Trivy, Prowler, Checkov, OpenSCAP output]
    end
    subgraph cspm
        HOOK[allowlist hook]
        COL[collectors]
        MODEL[(Resource model)]
        ENG[rule engine]
        RULES[rules]
        SCORE[scoring]
        MAP[mappings]
        ING[ingest]
        STORE[(SQLite store)]
        REP[reports]
        IAM[iam-review]
        TLS[tls and cert checks]
    end
    AWS --> HOOK --> COL
    AZ --> COL
    TF --> COL
    COL --> MODEL --> ENG
    RULES --> ENG
    ENG --> SCORE --> MAP --> STORE
    EXT --> ING --> STORE
    IAM --> STORE
    TLS --> STORE
    STORE --> REP
    REP --> OUT[JSON, SARIF, Markdown, HTML, manifest]
```

Flow: collectors call cloud APIs through the allowlist hook and return `Resource` objects. The engine runs every rule registered for a resource type and turns violations into `Finding` objects. Scoring sets score and band and mappings attach control references. The store then matches findings to earlier scans to move their lifecycle state. Reports read from the store.

The contracts in cspm/contracts are the seams between modules. See ADR 0001 to 0004.
