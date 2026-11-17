# Contributing to VaultX

Thank you for contributing to **VaultX**, a Manufacturing-Aware Hybrid Network Intrusion Detection System (NIDS) designed for Indian electronics manufacturing MSMEs.

This document outlines the development workflow, coding standards, branch conventions, and security disclosure procedures for all contributors.

---

## 1. Code of Conduct

We are committed to providing a collaborative, respectful, and productive environment. All contributors and maintainers are expected to adhere to high professional standards of technical collaboration.

---

## 2. Development Workflow & Branch Naming

### 2.1 Branch Conventions
All work should be performed in a dedicated feature, fix, or documentation branch cut from `main`.

Use the following naming patterns:
- `feature/<short-description>`: New system capabilities, parsers, or modules (e.g., `feature/zeek-modbus-parser`)
- `fix/<short-description>`: Bug fixes or schema corrections (e.g., `fix/retention-partition-range`)
- `docs/<short-description>`: Architecture guides, deployment documentation, API specs (e.g., `docs/dataset-matrix`)
- `infra/<short-description>`: Docker compose, network topologies, CI workflows (e.g., `infra/timescaledb-tuning`)
- `telemetry/<short-description>`: Sensor agents, packet capture scripts, log collectors (e.g., `telemetry/sysmon-rules`)

### 2.2 Commit Message Format
We follow the **Conventional Commits** specification:

```
<type>(<scope>): <short summary>

[optional body explaining context and rationale]

[optional footer(s) referencing issue numbers]
```

**Permitted Types:**
- `feat`: A new feature or analytical capability
- `fix`: A bug fix or schema patch
- `docs`: Documentation updates or additions
- `style`: Formatting changes that do not affect code logic
- `refactor`: Code restructuring without functional changes
- `test`: Adding or updating test cases
- `chore`: Build tooling, dependency bumps, or CI updates

**Examples:**
```
feat(ingestion): implement Redis stream backpressure handler
fix(schema): correct foreign key reference in incident_tables.sql
docs(topology): update VLAN 30 PLC IP allocation table
```

---

## 3. Code Standards and Formatting

### 3.1 Python
- **Python Version:** 3.11+
- **Style Standard:** Follow PEP 8 guidelines.
- **Linter & Formatter:**
  - `flake8` for syntax and style enforcement (max line length 100 characters).
  - `black` or `ruff` for automated formatting.
- **Type Annotations:** Use Python type hints (`typing` module) for all public functions, classes, and Pydantic models.
- **Asynchronous Code:** Use `asyncio` with explicit timeout handling for network/database I/O.

### 3.2 SQL
- Use lowercase keywords (`select`, `create table`, `partition by`) or consistent uppercase, as defined in `database/schema/`.
- Ensure all time-series tables define appropriate partition ranges and BRIN/B-tree indexes.
- Never write destructive migrations; test schema changes against staging instances first.

### 3.3 Infrastructure & Configuration
- **YAML / Docker Compose:** Indent with 2 spaces. Validate compose files with `docker compose config` prior to submitting.
- **JSON:** Ensure all machine-readable topology inventories (`assets.json`, `firewall_rules.json`) validate against standard JSON parsers with 2-space indentation.

---

## 4. Pull Request (PR) Process

1. **Verify Locally:**
   - Execute linter checks: `flake8`
   - Validate JSON and YAML schemas: `python -m json.tool <file>` and `docker compose config`
   - Confirm database migration syntax against PostgreSQL 15.
2. **Submit PR:**
   - Target the `main` branch.
   - Fill out the PR template describing the problem solved, testing performed, and any impact on OT or IT network segments.
3. **Continuous Integration (CI):**
   - Ensure all automated GitHub Actions checks pass (linting, schema validation, SQL syntax check, Docker configuration build).
4. **Code Review:**
   - At least one code review approval from a maintainer is required.
   - Any changes impacting VLAN 30 (Manufacturing OT) require explicit sign-off considering physical process safety.

---

## 5. Security Vulnerability Disclosure Policy

The VaultX team takes security seriously. If you discover a security vulnerability in VaultX or the BECPL reference simulation, please do **NOT** open a public issue.

Instead, report it via responsible disclosure:
1. Email: `security-disclosure@becpl.internal` (or project maintainers)
2. Include:
   - Detailed description of the vulnerability
   - Steps to reproduce or proof-of-concept
   - Impact assessment on IT/OT boundary isolation
   - Any suggested mitigations
3. Maintainers will acknowledge receipt within 48 hours and coordinate remediation before public release.
