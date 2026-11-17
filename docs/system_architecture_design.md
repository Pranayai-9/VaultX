# Electronics Manufacturing Cyber-Defense System Architecture

This document outlines the high-level architecture for a centralized cyber-defense system tailored for an electronics manufacturing environment, adhering to the security principles and functional requirements specified.

## Core System Components

The system is composed of three primary functional components working in concert to ensure visibility, detection, and response.

### 1. Manufacturing Infrastructure (Simulated)
A representative electronics manufacturing facility comprising:
*   **IT Segment:** Standard enterprise IT (workstations, servers, office network).
*   **OT Segment:** Industrial Control Systems (ICS), Programmable Logic Controllers (PLCs), human-machine interfaces (HMIs).
*   **Engineering/Firmware Segment:** Specialized build environments for device firmware.
*   **Inventory & Logistics:** ERP and supply-chain management systems.
*   **Third-party Integrations:** External vendor connections and cloud services.

### 2. Centralized Cyber-Defense Backend
This acts as the brain of the security infrastructure.
*   **Network Intelligence:** Collects data from distributed passive network sensors.
*   **Threat Detection Engine:** Analyzes data to identify anomalies and malicious patterns.
*   **Vulnerability Monitoring:** Tracks assets and identifies known security gaps.
*   **Log Intelligence:** Centralized repository for logs (audits, security events).
*   **Threat Correlation & Isolation:** Correlates disparate signals to make high-confidence decisions.

### 3. Security Command Dashboard
*   Visualizes the entire organization's security posture.
*   Displays active incidents and affected assets.
*   Provides controls for policy-driven isolation.
*   Facilitates human-authorized responses.

## Key Architectural Principles

1.  **Passive Distributed Sensors:** Deployment of passive network sensors distributed throughout the facility. These sensors relay telemetry to the central management system to avoid bottlenecking and latency in production networks.
2.  **Identity-Centric Telemetry:** Traffic analysis is augmented by endpoint and service telemetry. Distinctions are made between human users, service accounts, automated workloads, AI agents, and industrial devices to reduce false positives in threat detection.
3.  **Configurable Event Storage:** All generated security events, flow records, and audit logs are stored. Raw packet data is not indefinitely retained; instead, configurable retention and archival policies are applied based on data criticality.
4.  **Offline Model Retraining:** Security models are trained offline on validated, preprocessed historical datasets. Online/real-time training is restricted to avoid risks of label noise and data poisoning.
5.  **Policy-Driven Isolation:** Containment is automated but governed by policy. IT assets can be automatically quarantined, while safety-critical industrial equipment (e.g., PLCs) requires human authorization before disconnection, factoring in production safety dependencies.

## Data Integration Strategy

The system will leverage a multi-dataset approach to ensure robust threat detection:
*   **X-IIoTID:** Industrial-specific device-level threat detection.
*   **ToN_IoT:** Cross-domain telemetry correlation.
*   **CSE-CIC-IDS2018:** Large-scale enterprise network intrusion analysis.
*   **HAI 22.04 / 23.05:** ICS behavioral anomaly detection.
*   **Manufacturing Simulation Data:** Additional labelled traffic generated from internal manufacturing simulations to address domain-specific behavior.
