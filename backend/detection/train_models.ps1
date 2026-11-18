<#
.SYNOPSIS
    VaultX Offline ML Model Training & Human Approval Orchestration Script (PowerShell)
    BECPL (Bharat Electronics Components Pvt. Ltd.), Pune

.DESCRIPTION
    1. Activates a local Python virtualenv (.venv or venv) if present.
    2. Runs offline model_trainer.py with dataset path and version arguments.
    3. Prints evaluation summary from backend/models/evaluation_report_v<version>.json.
    4. Prompts for explicit human approval before marking the model as approved in ModelRegistry.

.EXAMPLE
    .\backend\detection\train_models.ps1 -DatasetPath datasets\processed\becpl_synthetic_traffic_50k.csv -Version 1
#>

param(
    [string]$DatasetPath = "",
    [string]$Version = "1",
    [string]$PythonBin = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$ModelDir = Join-Path $RepoRoot "backend\models"

if ([string]::IsNullOrWhiteSpace($DatasetPath)) {
    $DatasetPath = Join-Path $RepoRoot "datasets\processed\becpl_synthetic_traffic_50k.csv"
}

Write-Host "========================================================================"
Write-Host "VaultX Offline ML Model Training Pipeline (v$Version)"
Write-Host "Dataset : $DatasetPath"
Write-Host "Output  : $ModelDir"
Write-Host "========================================================================"

# 1. Activate virtualenv if present
$VenvCandidates = @(
    (Join-Path $RepoRoot ".venv\Scripts\Activate.ps1"),
    (Join-Path $RepoRoot "venv\Scripts\Activate.ps1")
)
$Activated = $false
foreach ($candidate in $VenvCandidates) {
    if (Test-Path $candidate) {
        Write-Host "[1/4] Activating virtualenv: $candidate"
        & $candidate
        $Activated = $true
        break
    }
}
if (-not $Activated) {
    Write-Host "[1/4] No local virtualenv found; using system Python."
}

if ([string]::IsNullOrWhiteSpace($PythonBin)) {
    if (Get-Command python -ErrorAction SilentlyContinue) {
        $PythonBin = "python"
    } elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
        $PythonBin = "python3"
    } else {
        throw "Python interpreter not found in PATH. Pass -PythonBin <path>."
    }
}

# 2. Run offline model trainer
Write-Host "[2/4] Running offline model_trainer.py..."
& $PythonBin (Join-Path $ScriptDir "model_trainer.py") `
    --dataset $DatasetPath `
    --version $Version `
    --output-dir $ModelDir

if ($LASTEXITCODE -ne 0) {
    throw "model_trainer.py failed with exit code $LASTEXITCODE"
}

# 3. Print evaluation summary
$ReportPath = Join-Path $ModelDir "evaluation_report_v$Version.json"
Write-Host ""
Write-Host "[3/4] Evaluation Summary ($ReportPath):"
$Report = Get-Content -Path $ReportPath -Raw | ConvertFrom-Json
$Rf = $Report.rf_classifier
$Iso = $Report.isolation_forest

Write-Host ("  Model Version           : v{0}" -f $Report.model_version)
Write-Host ("  Training Dataset        : {0}" -f $Report.training_dataset)
Write-Host ("  Train / Test Samples    : {0} / {1}" -f $Report.train_samples, $Report.test_samples)
Write-Host ("  RF Macro F1             : {0:N4}" -f $Rf.macro_f1)
Write-Host ("  RF Weighted F1          : {0:N4}" -f $Rf.weighted_f1)
Write-Host ("  RF False Positive Rate  : {0:P4}" -f $Rf.false_positive_rate)
Write-Host ("  RF Inference (1k flows) : {0:N2} ms" -f $Rf.inference_time_ms_per_1000_samples)
Write-Host ("  IF Attack Detection Rate: {0:P2}" -f $Iso.anomaly_detection_rate_on_attacks)
Write-Host ("  IF Benign FPR           : {0:P2}" -f $Iso.false_positive_rate_on_benign)

# 4. Prompt for human approval
Write-Host ""
Write-Host "[4/4] Human Governance Gate"
$Reply = Read-Host "Approve model v$Version for deployment? (yes/no)"
if ($Reply -eq "yes" -or $Reply -eq "YES") {
    $ApproverId = Read-Host "Enter Approver ID (e.g. sec-mgr-pune)"
    if ([string]::IsNullOrWhiteSpace($ApproverId)) {
        throw "Approval aborted: Approver ID cannot be empty."
    }
    $ApproveCode = @"
import sys
sys.path.insert(0, r'$RepoRoot')
from backend.detection.model_registry import ModelRegistry
reg = ModelRegistry(model_dir=r'$ModelDir')
reg.register_model(version_id='$Version', actor='$ApproverId')
rec = reg.approve_model(version_id='$Version', approver_id='$ApproverId', notes='Approved via train_models.ps1')
print(f'Model v{rec.version_id} marked APPROVED by {rec.approved_by} (action_id={rec.approval_action_id}).')
"@
    & $PythonBin -c $ApproveCode
} else {
    Write-Host "Model v$Version remains in 'candidate' state. No deployment changes made."
}
