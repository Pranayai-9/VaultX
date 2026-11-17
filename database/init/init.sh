#!/bin/bash
# ==============================================================================
# VaultX NIDS - Database Initialization Script
# Bharat Electronics Components Pvt. Ltd. (BECPL), Pune
# Runs on container initialization in postgres:15 (/docker-entrypoint-initdb.d/)
# ==============================================================================
set -e

echo "=========================================================="
echo " Starting VaultX NIDS Security Database Initialization..."
echo " Database: ${POSTGRES_DB:-vaultx_nids}"
echo " User:     ${POSTGRES_USER:-vaultx_admin}"
echo " Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "=========================================================="

INIT_DIR="/docker-entrypoint-initdb.d"

# Helper function to run SQL file with clear logging
run_sql_step() {
    local file_path="$1"
    local description="$2"
    
    echo "--> [Step] Applying: ${description} (${file_path})..."
    if [ -f "${file_path}" ]; then
        psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-vaultx_admin}" --dbname "${POSTGRES_DB:-vaultx_nids}" -f "${file_path}"
        echo "    [SUCCESS] Applied ${file_path}"
    else
        echo "    [ERROR] Missing required SQL file: ${file_path}"
        exit 1
    fi
}

# 1. Core Reference Tables
run_sql_step "${INIT_DIR}/01_core_tables.sql" "01 Core Reference Tables & Extensions"

# 2. Time Series Partitioned Tables
run_sql_step "${INIT_DIR}/02_time_series_tables.sql" "02 Time-Series Event & Flow Tables"

# 3. Incident, Response & Audit Tables
run_sql_step "${INIT_DIR}/03_incident_tables.sql" "03 Incident, Response & Audit Tables"

# 4. Performance, BRIN & GIN Indexes
run_sql_step "${INIT_DIR}/04_indexes.sql" "04 Performance Indexes"

# 5. Seed Data
run_sql_step "${INIT_DIR}/05_seed_data.sql" "05 BECPL Pune Seed Data & Reference Matrix"

echo "=========================================================="
echo " VaultX NIDS Database Initialization Completed Successfully!"
echo " Tables, partitions, and baseline seed data are ready."
echo "=========================================================="
