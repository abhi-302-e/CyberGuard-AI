# CyberGuard AI - System Architecture Specification

## 1. Executive Architecture Overview

**CyberGuard AI** is an autonomous multi-agent cybersecurity decision intelligence platform designed to ingest raw enterprise telemetry, detect threats, isolate vulnerabilities, correlate indicators with global threat intelligence, formulate policy-compliant defense strategies, execute containment, and adaptively improve detection rules over time without human intervention.

```mermaid
flowchart TD
    subgraph INGESTION["1. Telemetry Ingestion Layer"]
        A1["Agent 1: Security Data Collection Agent<br/>(Syslog, Firewall, EDR, NetFlow, SIEM)"]
    end

    subgraph PREPROCESSING["2. Anomaly & Filtering Layer"]
        A2["Agent 2: Security Data Analysis Agent<br/>(Noise Reduction, De-duplication, Heuristics)"]
    end

    subgraph DETECTION["3. Domain-Specific Detection Mesh (Parallel Fan-Out)"]
        A3["Agent 3: Threat Detection Agent<br/>(Sigma Rules & Attack Signatures)"]
        A4["Agent 4: Vulnerability Assessment Agent<br/>(CVE Mapping & CVSS Scoring)"]
        A5["Agent 5: Network Monitoring Agent<br/>(Zeek Flow & C2 Beaconing)"]
        A6["Agent 6: Malware Analysis Agent<br/>(YARA Rules & Static Sandbox)"]
    end

    subgraph CORRELATION["4. Intelligence Synthesis Layer (Fan-In)"]
        A7["Agent 7: Threat Intelligence Agent<br/>(MITRE ATT&CK & STIX 2.1)"]
    end

    subgraph DECISION["5. Decision & Governance Brain"]
        A8["Agent 8: Security Decision Agent<br/>(Risk Scoring & Policy Guardrail Gate)"]
    end

    subgraph GATING{"Threat Confirmed?"}
        G1{"Is Threat Confirmed?"}
    end

    subgraph AUTH_GATE{"Response Authorized?"}
        G2{"Autonomous Policy Match?"}
    end

    subgraph RESPONSE["6. Containment & Remediation"]
        A9["Agent 9: Automated Incident Response Agent<br/>(EDR Isolation, IP Drop, Token Revoke)"]
    end

    subgraph ESCALATION["Escalation Queue"]
        ESC["SOC Incident Commander / Tier-3 Human Review"]
    end

    subgraph VERIFICATION["7. Closed-Loop Learning & Verification"]
        A10["Agent 10: Monitoring & Self-Learning Agent<br/>(Post-Containment Check & Rule Weight Optimization)"]
    end

    A1 --> A2
    A2 --> A3 & A4 & A5 & A6
    A3 & A4 & A5 & A6 --> A7
    A7 --> A8
    A8 --> G1

    G1 -- "No (Benign Baseline)" --> BASELINE["Record to Baseline Memory & Continue Monitoring"]
    G1 -- "Yes" --> G2

    G2 -- "Requires Human Signoff (Tier-0 Asset)" --> ESC
    G2 -- "Approved Autonomous Policy" --> A9

    A9 --> V1{"Containment Verified?"}
    V1 -- "Yes" --> A10
    V1 -- "No" --> ESC
    A10 --> LOOP["Feedback Loop: Adaptive Rule Store Update"]
```

---

## 2. The 10 Specialized Agents

| # | Agent Name | Primary Responsibility | Input Contract | Output Contract | Tools / Technology |
|---|---|---|---|---|---|
| **1** | **Security Data Collection Agent** | Ingest raw telemetry across heterogeneous boundary appliances. | Raw JSON, Syslog, EDR events, Firewall logs | `List[SecurityEvent]` normalized dataclass | Python, Syslog, ELK APIs |
| **2** | **Security Data Analysis Agent** | Filter background noise, de-duplicate, identify deviations. | `List[SecurityEvent]` | `filtered_events`, `anomaly_events` | Pandas, NumPy, sliding time-window hashes |
| **3** | **Threat Detection Agent** | Detect active attack techniques via Sigma rules and attack heuristics. | Filtered anomalies | `List[ThreatDetection]` (MITRE TTPs, confidence) | Sigma, regex engine, behavioral heuristic models |
| **4** | **Vulnerability Assessment Agent** | Correlate software banners and assets with known CVE catalogs. | Host banners, versions | `List[VulnerabilityFinding]` (CVSS, remediation) | Nmap banners, CERT-In advisory database, OpenVAS |
| **5** | **Network Monitoring Agent** | Monitor connection rates, C2 beaconing, DNS tunneling, and egress spikes. | NetFlow, Zeek/Suricata logs | `List[NetworkAnomaly]` | Zeek, Wireshark, Suricata signatures |
| **6** | **Malware Analysis Agent** | Inspect scriptblocks, executable payloads, and file hashes. | Hashes, payloads, file metadata | `List[MalwareAnalysisResult]` | YARA rule engine, PE header checks, ClamAV |
| **7** | **Threat Intelligence Agent** | Correlate multi-agent findings, attribute threat actors, build narrative. | Multi-agent outputs (3, 4, 5, 6) | `ThreatIntelligenceReport` (STIX 2.1 bundle) | MITRE ATT&CK enterprise matrices, STIX/TAXII feeds |
| **8** | **Security Decision Agent** | Compute risk scores, evaluate policy guardrails, authorize actions. | Threat Intel Report | `SecurityDecisionPlan` (Prioritized actions, gating) | Risk Matrix: $Risk = S \times C \times Conf$, Policy ACLs |
| **9** | **Automated Incident Response Agent** | Execute authorized defensive actions without human delay. | Approved Decision Plan | `List[ActionResult]`, containment state | iptables, PFSense API, CrowdStrike/SentinelOne EDR API |
| **10** | **Monitoring & Self-Learning Agent** | Verify cessation of attack traffic, optimize detection weights. | Telemetry post-containment | `MonitoringMetrics`, dynamic rule adjustments | Feedback loop engine, rule store reinforcement |

---

## 3. Decision-Making & Risk Quantification Engine

Agent 8 evaluates composite risk using the following mathematical formulation:

$$\text{Risk Score} = \min\left(100, \, \text{Severity Multiplier} \times \text{Asset Criticality Multiplier} \times \text{Confidence Score}\right)$$

### Tier Classification
- **Severity Multiplier:** INFO (10), LOW (25), MEDIUM (50), HIGH (75), CRITICAL (95)
- **Asset Criticality Multiplier:**
  - Standard Workstation / DMZ Test: $1.0\times$
  - Business Application Server: $1.5\times$
  - Tier-0 Critical Asset (Active Directory DC, Primary Database, Root PKI): $2.0\times$
- **Authorization Gating:**
  - Standard containment (blocking attacker IPs, isolating standard workstations, revoking sessions) runs **autonomously** at confidence $\ge 0.80$.
  - High-impact operations on Tier-0 assets (e.g. isolating the primary database server) are automatically **gated for human sign-off** to prevent operational disruption.

---

## 4. Error Handling & Circuit Breaker Architecture

The orchestrator integrates `ErrorRecoveryManager` with:
1. **Exponential Backoff:** Retries failed tasks with $100\text{ms} \times 2^{\text{attempt}-1}$ delays.
2. **Circuit Breaker State Machine:**
   - `CLOSED`: Normal autonomous operation.
   - `OPEN`: Tripped after repeated failures; execution automatically diverts to safe fallback strategies.
   - `HALF-OPEN`: Probes whether recovery conditions are restored.
3. **Safety Validation Guardrails:** Every proposed decision is screened against destructive patterns (e.g. deleting system directories or flushing root firewall configurations). Malformed instructions trigger an immediate safety halt.

---

## 5. Self-Improvement & Continuous Learning Loop

Agent 10 feeds verified operational results back into `GLOBAL_LEARNING_ENGINE`:
1. **True Positive Reinforcement:** When containment is verified and threat is neutralized, matching detection rule weights are boosted by $+0.05$ (up to a ceiling of $1.50\times$).
2. **False Positive Suppression:** Unconfirmed or disputed alerts decrement rule weights by $-0.10$ (down to a floor of $0.40\times$).
3. **Closed-Loop Rule Optimization:** Ensures the system becomes progressively sharper, adapting to evolving adversary TTPs over time.

