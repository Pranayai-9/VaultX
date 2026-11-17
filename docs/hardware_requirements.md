# Hardware Requirements & Sizing Guide — VaultX

> **Document Version:** 1.0  
> **Target Audience:** IT/OT Infrastructure Engineers, Security System Integrators  
> **Scope:** Phase 1 Digital Twin & Lab Prototype, with Production Sizing Roadmap for Bharat Electronics Components Pvt. Ltd. (BECPL)

---

## 1. Overview & Architectural Sizing Context

VaultX is architected as a **distributed passive sensing** Network Intrusion Detection System (NIDS). Rather than backhauling full raw packet streams to a single centralized appliance, passive sensor nodes extract protocol metadata, netflows, and structured security notices locally across industrial VLANs. Only structured events and incident-triggered packet captures are transmitted over a dedicated out-of-band management network to the Central Security Management Cluster.

Consequently, hardware sizing is bifurcated into:
1. **Lab Prototype / Digital Twin Environment (Phase 1 Proof of Concept)**
2. **Production Deployment Baseline (Medium-Sized Electronics Manufacturing MSME)**

---

## 2. Minimum Lab Setup (Proof of Concept / Digital Twin)

The Phase 1 laboratory environment provides a representative hardware topology capable of running the containerized digital twin, database cluster, telemetry parsers, and sensor agents.

```
+----------------------------------------------------------------------------------+
|                              LAB NETWORK TOPOLOGY                                |
|                                                                                  |
|   +-------------------+              +---------------------------------------+   |
|   |  OPNsense Router  |              |        Managed L2/L3 Switch           |   |
|   |  (Inter-VLAN FW)  |              |  (MikroTik CRS326-24G-2S+RM)          |   |
|   +---------+---------+              +-------------------+-------------------+   |
|             |                                            |                       |
|             +====================== Trunk ===============+                       |
|                                                          |                       |
|         +-----------------------+                        | SPAN / Mirror Port    |
|         |                       |                        |                       |
|  +------+-------------+  +------+--------------+  +------+-------------+         |
|  |   Central Server   |  |   Workstations /    |  |    Sensor Node    |         |
|  | (Docker, DB, NIDS) |  |   Simulated Hosts   |  | (Zeek + Suricata)  |         |
|  |   8C / 32GB RAM    |  |  (Engineering / OT) |  |   4C / 8GB RAM    |         |
|  +--------------------+  +---------------------+  +--------------------+         |
+----------------------------------------------------------------------------------+
```

### 2.1 Hardware Bill of Materials (Lab Prototype)

| Component | Quantity | Minimum Specification | Recommended Model / Make | Primary Function |
|---|:---:|---|---|---|
| **Central Server** | 1 | 8 Cores (AMD Ryzen 7 5700X / Intel Core i7-11700), 32 GB DDR4 RAM, 2 TB NVMe SSD, 2× 1 Gbps NICs | Custom 1U/Tower or Dell PowerEdge R250 / HP MicroServer Gen10+ | Hosts Docker Compose stack: PostgreSQL 15, Redis Streams, MinIO S3 storage, NIDS orchestration |
| **Sensor Node** | 1 | 4 Cores (Intel Core i3 / Xeon E3 or AMD Ryzen 3), 8 GB RAM, 256 GB SATA SSD, 1× dedicated 1 Gbps/10 Gbps monitoring NIC + 1× 1 Gbps management NIC | Protectli Vault FW6 / Dell OptiPlex Small Form Factor / Advantech UNO | Runs Zeek and Suricata passive packet inspection engine, ships events via Redis Streams |
| **Managed Switch** | 1 | 24× Gigabit RJ45 ports + 2× 10G SFP+ uplinks, 802.1Q VLAN tagging, Port Mirroring / SPAN | MikroTik CRS326-24G-2S+RM or Cisco Catalyst 2960-X / CBS350-24T | Enforces VLAN segmentation (VLAN 10 through 70) and delivers mirrored SPAN traffic to the sensor node |
| **Router / Firewall** | 1 | 4 Cores, 4 GB RAM, 4× Gigabit NICs | OPNsense running on Protectli / Minisforum box or bare-metal appliance | Provides stateful inter-VLAN routing, perimeter NAT, and WireGuard vendor VPN termination |

### 2.2 Network Interface Configuration (Lab Sensor Node)
- **Monitoring Interface (`eth1` / `enp2s0`):** Promiscuous mode, **no IP address assigned**, hardware checksum offloading disabled (`ethtool -K eth1 rx off tx off tso off gso off gro off`), connected to the switch SPAN/mirror destination port.
- **Management Interface (`eth0` / `enp1s0`):** Static IP in VLAN 70 (Security Management: `10.10.70.21`), connected to normal switch access port for Redis Streams and SSH administration.

---

## 3. Important Limitations of the Lab Setup

The laboratory proof-of-concept environment provides faithful functional validation of protocols, schemas, and correlation logic, but possesses inherent physical boundaries:

> [!WARNING]
> **Performance Limitations of Lab SPAN Ports:**
> - **Line-Rate Saturation:** A Gigabit SPAN port cannot mirror duplex traffic exceeding 1 Gbps aggregate (500 Mbps TX + 500 Mbps RX). Peak manufacturing bursts will lead to switch egress drops.
> - **Software Packet Drop under High Packets-Per-Second (PPS):** In the lab node without kernel-bypass drivers (such as AF_PACKET fanout, DPDK, or PF_RING), Zeek and Suricata will drop packets when processing high-frequency industrial bursts (>300,000 PPS).
> - **Synthetic Latency:** Docker bridge networking across containerized VLANs introduces slight microsecond-level software latency compared to hardware ASIC switching.

---

## 4. Production Deployment Roadmap for BECPL

For full physical plant deployment across the 12,000 sq. ft. Bhosari MIDC campus, the single-sensor lab setup transitions to a **distributed physical appliance architecture**.

```
+----------------------------------------------------------------------------------+
|                       PRODUCTION DEPLOYMENT ARCHITECTURE                         |
|                                                                                  |
|    VLAN 10 Corporate IT       VLAN 20 Engineering       VLAN 30 Manufacturing OT |
|   +--------------------+     +--------------------+     +--------------------+   |
|   |  Passive Copper Tap|     |  Passive Copper Tap|     |  DIN-Rail Copper Tap|  |
|   +---------+----------+     +---------+----------+     +---------+----------+   |
|             | RX only                  | RX only                  | RX only      |
|   +---------v----------+     +---------v----------+     +---------v----------+   |
|   | Sensor 1: Corp IT  |     | Sensor 2: Eng/Dev  |     | Sensor 3: Plant OT |   |
|   | (1U Rack Appliance)|     | (1U Rack Appliance)|     | (DIN-Rail Fanless) |   |
|   +---------+----------+     +---------+----------+     +---------+----------+   |
|             | Out-of-band             | Out-of-band              | Out-of-band   |
|             +-------------------------+--------------------------+               |
|                                       | Management Network (VLAN 70)             |
|                                       v                                          |
|                         +----------------------------+                           |
|                         | Central Security Cluster   |                           |
|                         | - Dell PowerEdge R650 2U   |                           |
|                         | - 32 Cores / 64 GB RAM     |                           |
|                         | - 8 TB NVMe RAID 10        |                           |
|                         | - PostgreSQL + TimescaleDB |                           |
|                         | - MinIO Object Storage     |                           |
|                         +----------------------------+                           |
+----------------------------------------------------------------------------------+
```

### 4.1 Production Sensor Node Specifications

| Network Segment | Physical Location | Environmental Sizing | Compute & Memory | Network Interfaces |
|---|---|---|---|---|
| **VLAN 10 Corporate IT** | Main Server Room (Rack 1) | Standard 1U Rackmount, AC power | 8 Cores (Intel Xeon E-2336), 16 GB ECC RAM, 512 GB NVMe SSD | 2× 1 Gbps SPAN inputs + 1× 1 Gbps Mgmt NIC |
| **VLAN 20 Engineering** | Main Server Room (Rack 2) | Standard 1U Rackmount, AC power | 8 Cores (Intel Xeon E-2336), 16 GB ECC RAM, 512 GB NVMe SSD | 2× 1 Gbps SPAN inputs + 1× 1 Gbps Mgmt NIC |
| **VLAN 30 Manufacturing OT** | Shopfloor Control Cabinet (SMT Line A/B) | **DIN-rail mounted, fanless, IP40/IP50 rated, 24V DC industrial power supply**, operating range -20°C to 65°C | 6 Cores (Intel Atom x6425RE / Core i5 Industrial), 16 GB RAM, 256 GB Wide-Temp Industrial SSD | 2× 1 Gbps Hardware Tap inputs (zero packet loss) + 1× 1 Gbps isolated Mgmt NIC |
| **VLAN 40 Warehouse** | Logistics Hub Distribution Rack | Wall-mounted enclosure, dust filters | 4 Cores, 8 GB RAM, 256 GB SSD | 1× 1 Gbps SPAN input + 1× 1 Gbps Mgmt NIC |
| **VLAN 50 DMZ & Vendor** | Edge Telecom Rack | Standard 1U Rackmount | 8 Cores, 16 GB RAM, 512 GB NVMe SSD | 2× 1 Gbps Tap inputs + 1× 1 Gbps Mgmt NIC |

### 4.2 Central Security Cluster Sizing (Production Tier)
- **Compute:** Dual Intel Xeon Silver 4314 (32 cores / 64 threads) or AMD EPYC 7313P (16 cores / 32 threads).
- **Memory:** 64 GB to 128 GB DDR4-3200 ECC Registered RAM.
- **Primary Storage (Time-Series & Hot DB):** 4× 1.92 TB Enterprise Mixed-Use NVMe SSDs in hardware RAID 10 (~3.8 TB usable hot storage).
- **Secondary Storage (Cold Archive & MinIO PCAPs):** 4× 8 TB Enterprise SATA 7.2K HDDs in RAID 6 or connected Synology/TrueNAS NAS (16 TB usable cold storage).
- **Network:** 4× 1 Gbps RJ45 ports + 2× 10 Gbps SFP+ uplinks for telemetry ingestion and backup replication.
- **Power:** Dual redundant hot-plug 800W power supplies connected to dual online UPS sources.

---

## 5. Bandwidth & Storage Sizing Calculations

### 5.1 Telemetry Bandwidth on Management Network (VLAN 70)
In contrast to sending raw PCAP traffic (which would overwhelm the management subnet at 100–500 Mbps continuous load), VaultX passive sensors ship **pre-filtered JSON event objects** to Redis Streams:
- Average raw event size: 1.2 KB
- Peak event generation rate across all 5 sensors: 250 events/second
- Management bandwidth consumption:
  $$\text{Bandwidth} = 250 \times 1.2 \text{ KB/s} = 300 \text{ KB/s} \approx 2.4 \text{ Mbps}$$
- Even during extreme multi-stage attack simulations (1,500 events/sec), network overhead on VLAN 70 remains below **15 Mbps**, leaving ample capacity on standard 1 Gbps links.

### 5.2 Storage Growth Projections (PostgreSQL + MinIO)

| Storage Layer | Data Type | Average Daily Volume | 30-Day Volume | 90-Day Online Retention | 365-Day Cold Archive |
|---|---|---|---|---|---|
| **PostgreSQL (Hot)** | `security_events`, `network_flows` | 1.8 GB / day | 54 GB | 162 GB | N/A (partition pruned) |
| **PostgreSQL (Hot)** | `auth_events`, `endpoint_events` | 0.6 GB / day | 18 GB | 54 GB | N/A (partition pruned) |
| **MinIO (S3)** | Cold Compressed JSONL / Parquet | 0.5 GB / day | 15 GB | 45 GB | 182.5 GB |
| **MinIO (S3)** | Incident PCAP captures (15-min rolling trigger) | ~2.0 GB / incident (avg 2 incidents/week) | 16 GB | 48 GB | 104 GB |
| **MinIO (S3)** | ML Model Artifacts & Dataset Repositories | Static / Versioned | 35 GB | 35 GB | 50 GB |
| **TOTAL** | — | **~3.2 GB / day** | **~138 GB** | **~344 GB** | **~520 GB** |

A 2 TB NVMe drive provides over **3.5 years** of retention buffer under standard manufacturing operating conditions before requiring secondary cold migration.
