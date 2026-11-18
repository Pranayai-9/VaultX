#!/usr/bin/env bash
# ==============================================================================
# VaultX Offline ML Model Training & Human Approval Orchestration Script
# BECPL (Bharat Electronics Components Pvt. Ltd.), Pune
#
# Usage (Bash / Git Bash / WSL / Linux / macOS):
#   ./backend/detection/train_models.sh [dataset_path] [version]
#
# PowerShell equivalent:
#   See backend/detection/train_models.ps1 or run:
#     python backend/detection/model_trainer.py --dataset datasets/processed/becpl_synthetic_traffic_50k.csv --version 1
#
# Steps:
#   1. Activate Python virtualenv if present (.venv or venv, POSIX or Windows)
#   2. Execute offline model_trainer.py with dataset path and version number
#   3. Display evaluation summary from backend/models/evaluation_report_v<version>.json
#   4. Prompt human operator for explicit approval before marking model approved
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

DATASET_PATH="${1:-${REPO_ROOT}/datasets/processed/becpl_synthetic_traffic_50k.csv}"
MODEL_VERSION="${2:-1}"
MODEL_DIR="${REPO_ROOT}/backend/models"

echo "========================================================================"
echo "VaultX Offline ML Model Training Pipeline (v${MODEL_VERSION})"
echo "Dataset : ${DATASET_PATH}"
echo "Output  : ${MODEL_DIR}"
echo "========================================================================"

# 1. Activate virtualenv if present
if [ -f "${REPO_ROOT}/.venv/bin/activate" ]; then
    echo "[1/4] Activating virtualenv: ${REPO_ROOT}/.venv/bin/activate"
    # shellcheck disable=SC1091
    source "${REPO_ROOT}/.venv/bin/activate"
elif [ -f "${REPO_ROOT}/.venv/Scripts/activate" ]; then
    echo "[1/4] Activating Windows virtualenv: ${REPO_ROOT}/.venv/Scripts/activate"
    # shellcheck disable=SC1091
    source "${REPO_ROOT}/.venv/Scripts/activate"
elif [ -f "${REPO_ROOT}/venv/bin/activate" ]; then
    echo "[1/4] Activating virtualenv: ${REPO_ROOT}/venv/bin/activate"
    # shellcheck disable=SC1091
    source "${REPO_ROOT}/venv/bin/activate"
elif [ -f "${REPO_ROOT}/venv/Scripts/activate" ]; then
    echo "[1/4] Activating Windows virtualenv: ${REPO_ROOT}/venv/Scripts/activate"
    # shellcheck disable=SC1091
    source "${REPO_ROOT}/venv/Scripts/activate"
else
    echo "[1/4] No local virtualenv found; using system Python."
fi

PYTHON_BIN="${PYTHON_BIN:-$(command -v python3 || command -v python)}"
if [ -z "${PYTHON_BIN}" ]; then
    echo "ERROR: Python interpreter not found in PATH." >&2
    exit 1
fi

# 2. Run offline model trainer
echo "[2/4] Running offline model_trainer.py..."
"${PYTHON_BIN}" "${SCRIPT_DIR}/model_trainer.py" \
    --dataset "${DATASET_PATH}" \
    --version "${MODEL_VERSION}" \
    --output-dir "${MODEL_DIR}"

# 3. Print evaluation summary
REPORT_PATH="${MODEL_DIR}/evaluation_report_v${MODEL_VERSION}.json"
echo ""
echo "[3/4] Evaluation Summary (${REPORT_PATH}):"
"${PYTHON_BIN}" - "${REPORT_PATH}" << 'PYEOF'
import json, sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    report = json.load(fh)

rf = report["rf_classifier"]
iso = report["isolation_forest"]

print(f"  Model Version           : v{report['model_version']}")
print(f"  Training Dataset        : {report['training_dataset']}")
print(f"  Train / Test Samples    : {report['train_samples']} / {report['test_samples']}")
print(f"  RF Macro F1             : {rf['macro_f1']:.4f}")
print(f"  RF Weighted F1          : {rf['weighted_f1']:.4f}")
print(f"  RF False Positive Rate  : {rf['false_positive_rate']:.4%}")
print(f"  RF Inference (1k flows) : {rf['inference_time_ms_per_1000_samples']:.2f} ms")
print(f"  IF Attack Detection Rate: {iso['anomaly_detection_rate_on_attacks']:.4%}")
print(f"  IF Benign FPR           : {iso['false_positive_rate_on_benign']:.4%}")
print("  Limitations:")
for lim in report.get("limitations", []):
    print(f"    - {lim}")
PYEOF

# 4. Prompt for human approval before marking model as approved
echo ""
echo "[4/4] Human Governance Gate"
read -r -p "Approve model v${MODEL_VERSION} for deployment? (yes/no): " APPROVAL_REPLY

if [ "${APPROVAL_REPLY}" = "yes" ] || [ "${APPROVAL_REPLY}" = "YES" ]; then
    read -r -p "Enter Approver ID (e.g. sec-mgr-pune): " APPROVER_ID
    if [ -z "${APPROVER_ID}" ]; then
        echo "Approval aborted: Approver ID cannot be empty." >&2
        exit 1
    fi
    "${PYTHON_BIN}" - "${MODEL_DIR}" "${MODEL_VERSION}" "${APPROVER_ID}" "${REPO_ROOT}" << 'PYEOF'
import sys
sys.path.insert(0, sys.argv[4])
from backend.detection.model_registry import ModelRegistry

model_dir, version, approver_id = sys.argv[1], sys.argv[2], sys.argv[3]
reg = ModelRegistry(model_dir=model_dir)
reg.register_model(version_id=version, actor=approver_id)
rec = reg.approve_model(version_id=version, approver_id=approver_id, notes="Approved via train_models.sh")
print(f"Model v{rec.version_id} marked APPROVED by {rec.approved_by} (action_id={rec.approval_action_id}).")
PYEOF
else
    echo "Model v${MODEL_VERSION} remains in 'candidate' state. No deployment changes made."
fi
