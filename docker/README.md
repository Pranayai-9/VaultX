# VaultX: BECPL Manufacturing Environment Digital Twin Simulation

This directory contains the Docker-based digital twin simulation of the **Bharat Electronics Components Pvt. Ltd. (BECPL)** manufacturing facility in Pune, Maharashtra.

This simulation provides a high-fidelity synthetic environment for developing, training, and benchmarking the **VaultX Manufacturing-Aware Hybrid Network Intrusion Detection System (NIDS)**.

> **DISCLAIMER:** This environment is strictly for security research, threat simulation, and NIDS algorithm evaluation. No actual industrial production machinery or proprietary firmware is connected.

---

## 1. Network Architecture & VLAN Mapping

The simulation reproduces BECPL's 7 segmented security zones using isolated Docker user-defined bridge networks. Each Docker network models an enterprise VLAN subnet with dedicated IPAM assignments:

| VLAN ID | Segment Name | Logical Enterprise Subnet | Docker Bridge Network | Docker Subnet | Gateway |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **VLAN 10** | Corporate IT | `10.10.10.0/24` | `net_corporate` | `172.20.10.0/24` | `172.20.10.1` |
| **VLAN 20** | Engineering & Firmware | `10.10.20.0/24` | `net_engineering` | `172.20.20.0/24` | `172.20.20.1` |
| **VLAN 30** | OT / Manufacturing | `10.10.30.0/24` | `net_ot` | `172.20.30.0/24` | `172.20.30.1` |
| **VLAN 40** | Warehouse & Logistics | `10.10.40.0/24` | `net_warehouse` | `172.20.40.0/24` | `172.20.40.1` |
| **VLAN 50** | DMZ & Vendor Access | `10.10.50.0/24` | `net_dmz` | `172.20.50.0/24` | `172.20.50.1` |
| **VLAN 60** | Cloud & External Integrations | `10.10.60.0/24` | `net_cloud` | `172.20.60.0/24` | `172.20.60.1` |
| **VLAN 70** | Security Management Zone | `10.10.70.0/24` | `net_security` | `172.20.70.0/24` | `172.20.70.1` |

---

## 2. Service Inventory & Static IP Directory

### VLAN 10: Corporate IT (`compose/corporate.yml`)
| Container / Service | Role | IP Address | Internal Port | Host Port |
| :--- | :--- | :--- | :--- | :--- |
| `becpl-dns-server` | CoreDNS Internal Resolver (`becpl.local`) | `172.20.10.5` | 53/udp | `5353/udp` |
| `becpl-erp-server` | Odoo 16 ERP Suite | `172.20.10.10` | 8069 | Internal |
| `becpl-db-postgres` | PostgreSQL 15 (ERP Database) | `172.20.10.11` | 5432 | Internal |
| `becpl-ldap-server` | OpenLDAP Directory Server | `172.20.10.12` | 389, 636 | Internal |
| `becpl-file-server` | Nginx Corporate Document Share | `172.20.10.13` | 80 | Internal |
| `becpl-backup-server`| Centralized Backup Server (rsync/SSH) | `172.20.10.20` | 22, 873 | Internal |
| `becpl-admin-workstation` | IT Administrator Workstation | `172.20.10.30` | - | - |
| `becpl-corp-ws-[1..3]`| Finance, HR, Procurement Workstations | `172.20.10.31-33` | - | - |

### VLAN 20: Engineering & Firmware (`compose/engineering.yml`)
| Container / Service | Role | IP Address | Internal Port | Host Port |
| :--- | :--- | :--- | :--- | :--- |
| `becpl-gitea-server` | Gitea Git Firmware Repository | `172.20.20.10` | 3000, 22 | `3000` |
| `becpl-ci-server` | Jenkins LTS Build & Release Pipeline | `172.20.20.11` | 8080, 50000 | `8080` |
| `becpl-firmware-storage` | Nginx Firmware Binary Distribution | `172.20.20.13` | 80 | Internal |
| `becpl-eng-file-server` | Engineering Schematics & BOM Storage | `172.20.20.14` | 80 | Internal |
| `becpl-firmware-release`| Firmware Staging & Approval Service | `172.20.20.15` | - | - |
| `becpl-eng-ws-[1..2]` | Electronics Design Workstations | `172.20.20.30-31` | - | - |
| `becpl-firmware-dev-ws` | Dedicated Firmware Development Workstation | `172.20.20.32` | - | - |

### VLAN 30: OT / Manufacturing (`compose/ot.yml`)
| Container / Service | Role | IP Address | Internal Port | Host Port |
| :--- | :--- | :--- | :--- | :--- |
| `becpl-openplc-runtime` | Simulated OpenPLC Runtime | `172.20.30.10` | 502 (Modbus) | `502` |
| `becpl-hmi-nodered` | Node-RED Industrial HMI Dashboard | `172.20.30.11` | 1880 | `1880` |
| `becpl-mes-server` | Manufacturing Execution System (Flask) | `172.20.30.12` | 5000 | `5010` |
| `becpl-production-monitor` | Production Line Telemetry Aggregator | `172.20.30.13` | - | - |
| `becpl-modbus-simulator` | Pymodbus Multi-Register TCP Server | `172.20.30.14` | 502 (Modbus) | `5020` |
| `becpl-industrial-sensor-1`| Solder Wave Line Temperature/Pressure Sensor | `172.20.30.21` | - | - |
| `becpl-industrial-sensor-2`| Conveyor Speed & Board Counter Sensor | `172.20.30.22` | - | - |

### VLAN 40: Warehouse & Logistics (`compose/warehouse.yml`)
| Container / Service | Role | IP Address | Internal Port | Host Port |
| :--- | :--- | :--- | :--- | :--- |
| `becpl-wms-server` | Warehouse Management System (Flask) | `172.20.40.10` | 5000 | `5030` |
| `becpl-inventory-db` | PostgreSQL 15 Inventory Database | `172.20.40.11` | 5432 | Internal |
| `becpl-barcode-terminal` | Barcode Scanner Terminal Simulation | `172.20.40.12` | - | - |
| `becpl-dispatch-workstation`| Shipping Coordinator Workstation | `172.20.40.13` | - | - |
| `becpl-supplier-integration` | Global Component Supplier PO Gateway | `172.20.40.14` | 5000 | `5040` |
| `becpl-logistics-api` | DTDC / BlueDart Shipping Tracking API | `172.20.40.15` | 5000 | `5050` |

### VLAN 50: DMZ & Vendor Access (`compose/dmz.yml`)
| Container / Service | Role | IP Address | Internal Port | Host Port |
| :--- | :--- | :--- | :--- | :--- |
| `becpl-edge-firewall` | Nginx Edge Reverse Proxy / Simulated FW | `172.20.50.5` | 80, 443 | `8090` |
| `becpl-vpn-gateway` | WireGuard Remote Access Gateway | `172.20.50.10` | 51820/udp | `51820/udp` |
| `becpl-vendor-access-gw` | Controlled Vendor Portal Gateway | `172.20.50.11` | 80 | Internal |
| `becpl-reverse-proxy` | DMZ Internal Reverse Proxy | `172.20.50.12` | 80 | `8095` |
| `becpl-dmz-supplier-api` | DMZ Supplier Catalog & Order Endpoint | `172.20.50.13` | 5000 | `5060` |

### VLAN 60: Cloud & External Integration (`compose/cloud.yml`)
| Container / Service | Role | IP Address | Internal Port | Host Port |
| :--- | :--- | :--- | :--- | :--- |
| `becpl-cloud-storage-sim` | MinIO Cloud S3 Simulation (AWS India) | `172.20.60.10` | 9000, 9001 | `9010`, `9011` |
| `becpl-external-dev-service`| External Firmware Partner Portal | `172.20.60.11` | 80 | Internal |
| `becpl-ai-service-account` | AI Quality & Demand Forecasting Workload | `172.20.60.12` | - | - |

### VLAN 70: Security Management Zone (`compose/security.yml`)
| Container / Service | Role | IP Address | Internal Port | Host Port |
| :--- | :--- | :--- | :--- | :--- |
| `vaultx-nids-central` | VaultX NIDS Central Server (Phase 1 Stub) | `172.20.70.10` | 8080 | `8070` |
| `vaultx-security-db` | PostgreSQL 15 Security Events DB | `172.20.70.11` | 5432 | Internal |
| `vaultx-redis-streams` | Redis 7 Streams Event Bus | `172.20.70.12` | 6379 | Internal |
| `vaultx-minio-storage` | MinIO PCAP & Model Object Storage | `172.20.70.13` | 9000, 9001 | `9000`, `9001` |
| `vaultx-sensor-manager` | Distributed Sensor Manager (Stub) | `172.20.70.14` | 8081 | Internal |
| `vaultx-isolation-engine`| Automated Network Isolation Engine (Stub)| `172.20.70.15` | 8082 | Internal |

---

## 3. Getting Started

### Prerequisites
- Docker Engine 24.0+ & Docker Compose v2.20+ (supports `include:` syntax)
- Minimum 8 GB available RAM (16 GB recommended for running all 7 segments simultaneously)
- Python 3.10+ (for running test scripts or local simulators outside Docker)

### Starting the Simulation

1. **Launch the entire multi-segment stack:**
   ```bash
   cd docker
   docker compose up -d
   ```

2. **Verify running containers and networks:**
   ```bash
   docker compose ps
   docker network ls | grep net_
   ```

3. **Launch specific segments independently (for low-resource machines):**
   ```bash
   # Start only the OT segment
   docker compose -f compose/ot.yml up -d

   # Start only the Security management stack
   docker compose -f compose/security.yml up -d
   ```

4. **Tear down the stack and clean up networks:**
   ```bash
   docker compose down
   # To remove volumes as well:
   docker compose down -v
   ```

---

## 4. Key Service Web & API Interfaces

| Service | Local URL / Endpoint | Credentials | Purpose |
| :--- | :--- | :--- | :--- |
| **Gitea Git Server** | [http://localhost:3000](http://localhost:3000) | Setup wizard / `gitea_admin` | Firmware version control & code review |
| **Jenkins CI/CD** | [http://localhost:8080](http://localhost:8080) | (Initial setup in logs) | Automated firmware compilation & tests |
| **Node-RED HMI** | [http://localhost:1880](http://localhost:1880) | No auth required | Manufacturing HMI dashboard & flow designer |
| **OpenPLC Runtime** | Modbus TCP `localhost:502` | - | Simulated PLC register ladder logic |
| **Modbus Simulator** | Modbus TCP `localhost:5020` | - | Holding registers 40001-40005 |
| **MES Server** | [http://localhost:5010/status](http://localhost:5010/status) | Public API | Production job status and quality yield |
| **WMS Server** | [http://localhost:5030/inventory](http://localhost:5030/inventory) | Public API | Stock balance, receiving, dispatch |
| **VaultX MinIO (Security)** | [http://localhost:9001](http://localhost:9001) | `minio` / `minio123` | Security artifacts, PCAPs, baseline models |
| **MinIO (Cloud Sim)** | [http://localhost:9011](http://localhost:9011) | `minio` / `minio123` | Simulated external cloud storage buckets |
| **VaultX NIDS Central** | [http://localhost:8070/status](http://localhost:8070/status) | - | Phase 1 health and monitoring endpoint |

---

## 5. Industrial Simulation Details

### Modbus TCP Registers (OT Segment)
The `modbus-simulator` (`172.20.30.14:502`) and `openplc-runtime` expose standard Modbus TCP holding registers that are dynamically updated every 2 seconds:
- **40001 (Offset 0):** Solder Reflow Temperature (`°C * 10`, nominal 235.0 °C)
- **40002 (Offset 1):** Wave Solder Nitrogen Pressure (`PSI * 10`, nominal 62.0 PSI)
- **40003 (Offset 2):** SMT Conveyor Speed (`mm/s`, nominal 485 mm/s)
- **40004 (Offset 3):** Daily Finished Unit Count (increments monotonically)
- **40005 (Offset 4):** Alarm Status Flag (`0` = OK, `1` = Caution, `2` = High Temp Overtemp Alarm)

The `industrial-sensor-1` and `industrial-sensor-2` containers continuously poll these registers and stream JSON-formatted telemetry to `stdout`.

### Custom REST APIs
- **MES API (`docker/scripts/ot/mes_server.py`):**
  - `GET /status` — Overall equipment effectiveness (OEE) and plant health
  - `GET /production/jobs` — Active and queued PCB assembly jobs
  - `POST /production/jobs` — Schedule a new manufacturing run
  - `GET /quality/metrics` — Automated Optical Inspection (AOI) defects and yields
- **WMS API (`docker/scripts/warehouse/wms_server.py`):**
  - `GET /inventory` — Real-time component stock levels and valuations
  - `POST /inventory/receive` — Inbound goods receiving record
  - `GET /shipments` — Outbound dispatch orders and status
  - `POST /shipments/dispatch` — Release stock for customer shipment
- **Supplier Gateway (`docker/scripts/warehouse/supplier_integration.py`):**
  - `GET /orders` — Purchase orders placed with Taiwan/China/Domestic vendors
  - `POST /orders/acknowledge` — Supplier delivery confirmation
  - `GET /delivery-status` — International customs and air freight tracking

---

## 6. Simulation Limitations vs. Physical Manufacturing Environments

1. **Layer 2 Protocol Fidelity:**
   Standard Docker bridge networks simulate Layer 3 IP routing and isolation. Layer 2 broadcast phenomena (ARP spoofing, STP loops, LLDP discovery, IEEE 802.1Q tagging) are abstracted. In Phase 2/3 hardware testbeds, Macvlan or Open vSwitch may be used if raw L2 attack testing is needed.

2. **Serial Industrial Fieldbuses:**
   Physical MSME manufacturing lines commonly use RS-485 / Modbus RTU or CAN bus for lower-level actuators. In this simulation, fieldbus communication is encapsulated directly over Modbus TCP.

3. **Real-time Determinism (Jitter):**
   Standard Linux CFS and Docker container CPU scheduling do not guarantee hard real-time cycle times (e.g. 1ms PROFINET / EtherCAT determinism). Modbus polling rates are modeled at soft real-time intervals (500ms - 5s).

4. **Air-gap Simulation:**
   In the physical architecture, OT (VLAN 30) has no default gateway to the public internet and strictly controlled access through the DMZ/jump host. In Docker, `net_ot` does not route externally; cross-VLAN communication is governed by container attachment or simulated firewall forwarders.

5. **Hardware Security Modules (HSMs):**
   Firmware signing operations in the simulation use software-based staging scripts rather than physical PKCS#11 hardware security modules.
