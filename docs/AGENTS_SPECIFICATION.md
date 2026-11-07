# CyberGuard AI - Specialized Agent Specifications

Detailed technical specification for each of the 10 agents in the CyberGuard AI architecture.

---

### Agent 1: Security Data Collection Agent
- **ID:** `AGENT-01-INGEST`
- **Role:** Enterprise Security Data Ingestion & Normalization
- **Receives:** Raw unstructured and semi-structured security logs (Syslog RFC 5424, Windows Event Logs, NetFlow v9/IPFIX, Suricata EVE.json, CrowdStrike EDR telemetry, AWS CloudTrail).
- **Decides:** Validates payload schema, decodes timestamps to UTC epoch, maps proprietary field names to standard `SecurityEvent` schema, and discards unparseable corrupt frames.
- **Passes Forward:** `state.normalized_events` (`List[SecurityEvent]`).
- **Failure Mode & Recovery:** Buffers unparsed events to dead-letter queue; emits metric alarm if collection coverage drops below 95%.

---

### Agent 2: Security Data Analysis Agent
- **ID:** `AGENT-02-ANALYSIS`
- **Role:** Noise Filtering, De-duplication & Anomaly Flagging
- **Receives:** `state.normalized_events` from Agent 1.
- **Decides:**
  - Evaluates sliding 5-second temporal hash fingerprints to collapse duplicated alert storms.
  - Drops routine benign noise (NTP syncs, LLMNR discovery, internal broadcast).
  - Scores events against statistical anomaly baselines (rare ports, failed auth spikes, suspicious process substrings).
- **Passes Forward:** `state.filtered_events` and prioritized `state.anomaly_events`.
- **Failure Mode & Recovery:** If anomaly classifier fails, defaults to fail-open forwarding of all non-duplicate events to detection agents.

---

### Agent 3: Threat Detection Agent
- **ID:** `AGENT-03-DETECTION`
- **Role:** Signature & Anomaly-Based Attack Detection
- **Receives:** Filtered anomalous events from Agent 2.
- **Decides:**
  - Matches activity against Sigma behavioral rules (e.g. `w3wp.exe` spawning sub-shells, long password brute force, ransomware canary writes).
  - Categorizes attack types (Initial Access, Credential Access, Impact, Privilege Escalation).
- **Passes Forward:** `state.threat_detections` (`List[ThreatDetection]`) with MITRE technique codes and confidence scores.
- **Failure Mode & Recovery:** Fallback to generic regex heuristic if rule compiler encounters memory pressure.

---

### Agent 4: Vulnerability Assessment Agent
- **ID:** `AGENT-04-VULN`
- **Role:** Infrastructure Weakness & CVE Correlation
- **Receives:** Asset banners, software inventory versions, and filtered event telemetry.
- **Decides:**
  - Cross-references versions against vulnerability databases (including CERT-In advisories: CIVN-2026-0539 Linux Kernel UAF, CIVN-2026-0540 Drupal RCE, CVE-2026-123158 OpenSSH SSHole, CVE-2026-19868 SonicWall SAML bypass, CVE-2025-53770 SharePoint ToolShell).
  - Determines if detected vulnerable services are exposed to untrusted network segments.
- **Passes Forward:** `state.vulnerability_findings` (`List[VulnerabilityFinding]`).

---

### Agent 5: Network Monitoring Agent
- **ID:** `AGENT-05-NETWORK`
- **Role:** Traffic Flow, C2 Beaconing & Protocol Anomaly Detection
- **Receives:** Network flow metadata, connection intervals, DNS queries, packet statistics.
- **Decides:**
  - Detects low-jitter periodic beaconing to external IPs.
  - Detects data exfiltration (>50MB egress anomalies).
  - Identifies horizontal/vertical port scans and DNS tunneling.
- **Passes Forward:** `state.network_anomalies` (`List[NetworkAnomaly]`).

---

### Agent 6: Malware Analysis Agent
- **ID:** `AGENT-06-MALWARE`
- **Role:** File Behavior, Hash Reputation & YARA Static Analysis
- **Receives:** File hashes (SHA-256), scriptblocks, email attachments, memory dumps.
- **Decides:**
  - Matches strings against YARA rules (Storm-2603 Warlock payloads, Dharma/Has ransomware, AsyncRAT).
  - Evaluates PowerShell base64-encoded command lines and evasion switches.
- **Passes Forward:** `state.malware_analyses` (`List[MalwareAnalysisResult]`).

---

### Agent 7: Threat Intelligence Agent
- **ID:** `AGENT-07-INTEL`
- **Role:** Multi-Source Threat Correlation & ATT&CK Mapping
- **Receives:** Outputs from Agents 3, 4, 5, and 6.
- **Decides:**
  - Determines if multi-agent evidence forms a cohesive attack campaign.
  - Attributes attack to known adversary groups (e.g. Storm-2603, Dharma Syndicate).
  - Computes composite confidence and overall severity (CRITICAL, HIGH, MEDIUM, LOW).
- **Passes Forward:** `state.threat_intel_report` (Structured narrative + STIX 2.1 bundle) and `state.threat_confirmed`.

---

### Agent 8: Security Decision & Risk Assessment Agent
- **ID:** `AGENT-08-DECISION`
- **Role:** Risk Quantification, Response Strategy & Authorization Gate
- **Receives:** `state.threat_intel_report`.
- **Decides:**
  - Calculates risk score: $\text{Severity} \times \text{Criticality} \times \text{Confidence}$.
  - Selects defensive playbooks (IP drop, host isolation, session revocation).
  - Enforces policy gating: Autonomous action for standard assets; mandatory human approval gate for Tier-0 critical infrastructure.
- **Passes Forward:** `state.decision_plan` (`SecurityDecisionPlan`) and `state.response_authorized`.

---

### Agent 9: Automated Incident Response Agent
- **ID:** `AGENT-09-RESPONSE`
- **Role:** Active Defensive Execution & Policy Enforcement
- **Receives:** Authorized `state.decision_plan`.
- **Decides:**
  - Verifies safety constraints.
  - Dispatches execution calls to network firewalls, EDR agents, and identity providers.
  - Generates auditable SOC tickets (Jira/ServiceNow) and notification alerts.
- **Passes Forward:** `state.executed_actions` (`List[ActionResult]`) and `state.containment_successful`.

---

### Agent 10: Monitoring and Self-Learning Agent
- **ID:** `AGENT-10-LEARN`
- **Role:** Verification, False-Positive Optimization & Rule Evolution
- **Receives:** Telemetry following containment actions and incident execution logs.
- **Decides:**
  - Verifies that malicious flows and unauthorized processes have ceased.
  - Evaluates whether alerts were true positives or false alarms.
  - Computes performance metrics (MTTD, MTTR).
  - Adjusts dynamic rule confidence weights in the learning store.
- **Passes Forward:** `state.monitoring_metrics`, `state.final_report_markdown`, and closes autonomous workflow.

