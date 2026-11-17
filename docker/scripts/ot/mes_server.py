#!/usr/bin/env python3
"""
BECPL Manufacturing Execution System (MES) Simulation Server
Simulates production job scheduling, tracking, line performance, and quality metrics
for Bharat Electronics Components Pvt. Ltd. (Pune Plant 1).
"""

import os
import time
import random
import uuid
from datetime import datetime, timezone
from flask import Flask, jsonify, request

app = Flask(__name__)

SITE_ID = os.getenv("MES_SITE", "BECPL-PUNE-PLANT1")
START_TIME = datetime.now(timezone.utc)

# Initial sample production jobs
PRODUCTION_JOBS = [
    {
        "job_id": "JOB-2026-0891",
        "product_code": "PCB-CTRL-V2",
        "description": "Automotive ECU Controller Board Rev 2.1",
        "batch_number": "BCH-26-11-A1",
        "target_quantity": 500,
        "completed_quantity": 420,
        "scrap_quantity": 8,
        "status": "RUNNING",
        "line_id": "LINE-SMT-01",
        "priority": "HIGH",
        "operator_id": "OP-104",
        "started_at": "2026-11-17T06:00:00Z",
        "estimated_completion": "2026-11-17T18:00:00Z"
    },
    {
        "job_id": "JOB-2026-0892",
        "product_code": "IOT-SNS-TEMP",
        "description": "Industrial Wireless Temperature & Humidity Sensor",
        "batch_number": "BCH-26-11-B3",
        "target_quantity": 1200,
        "completed_quantity": 1200,
        "scrap_quantity": 14,
        "status": "COMPLETED",
        "line_id": "LINE-PTH-02",
        "priority": "NORMAL",
        "operator_id": "OP-209",
        "started_at": "2026-11-16T08:30:00Z",
        "estimated_completion": "2026-11-17T04:15:00Z"
    },
    {
        "job_id": "JOB-2026-0893",
        "product_code": "EMB-BLE-MOD",
        "description": "BLE 5.2 Micro-Module with Integrated Ceramic Antenna",
        "batch_number": "BCH-26-11-C1",
        "target_quantity": 2500,
        "completed_quantity": 1150,
        "scrap_quantity": 19,
        "status": "RUNNING",
        "line_id": "LINE-SMT-02",
        "priority": "NORMAL",
        "operator_id": "OP-115",
        "started_at": "2026-11-17T09:00:00Z",
        "estimated_completion": "2026-11-18T02:00:00Z"
    },
    {
        "job_id": "JOB-2026-0894",
        "product_code": "PWR-CONV-48V",
        "description": "48V to 12V Step-Down Synchronous Buck Converter",
        "batch_number": "BCH-26-11-D1",
        "target_quantity": 350,
        "completed_quantity": 0,
        "scrap_quantity": 0,
        "status": "QUEUED",
        "line_id": "LINE-SMT-01",
        "priority": "LOW",
        "operator_id": "UNASSIGNED",
        "started_at": None,
        "estimated_completion": "2026-11-19T12:00:00Z"
    }
]

PRODUCTION_LINES = [
    {
        "line_id": "LINE-SMT-01",
        "name": "Surface Mount Technology Line 1 (Yamaha YS24)",
        "status": "OPERATIONAL",
        "speed_cph": 24000,
        "target_cph": 25000,
        "oee_percent": 86.4
    },
    {
        "line_id": "LINE-SMT-02",
        "name": "Surface Mount Technology Line 2 (Fuji NXT III)",
        "status": "OPERATIONAL",
        "speed_cph": 32000,
        "target_cph": 35000,
        "oee_percent": 89.1
    },
    {
        "line_id": "LINE-PTH-01",
        "name": "Plated Through Hole Manual Wave Soldering",
        "status": "STANDBY",
        "speed_cph": 1200,
        "target_cph": 1500,
        "oee_percent": 74.8
    },
    {
        "line_id": "LINE-PTH-02",
        "name": "Plated Through Hole Selective Solder Cell",
        "status": "OPERATIONAL",
        "speed_cph": 1800,
        "target_cph": 2000,
        "oee_percent": 81.3
    }
]


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "BECPL Manufacturing Execution System",
        "site": SITE_ID,
        "version": "1.4.2",
        "endpoints": [
            "/status",
            "/production/jobs",
            "/production/jobs (POST)",
            "/quality/metrics",
            "/lines"
        ]
    })


@app.route("/status", methods=["GET"])
def get_status():
    uptime_seconds = (datetime.now(timezone.utc) - START_TIME).total_seconds()
    # Add slight realistic fluctuations
    active_lines = sum(1 for line in PRODUCTION_LINES if line["status"] == "OPERATIONAL")
    running_jobs = sum(1 for job in PRODUCTION_JOBS if job["status"] == "RUNNING")
    
    return jsonify({
        "status": "HEALTHY",
        "site_id": SITE_ID,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": round(uptime_seconds, 1),
        "total_lines": len(PRODUCTION_LINES),
        "active_lines": active_lines,
        "running_jobs": running_jobs,
        "overall_plant_oee": round(83.5 + random.uniform(-1.5, 1.5), 2),
        "shift": "Shift 2 (14:00 - 22:00 IST)",
        "shift_supervisor": "S. Deshmukh (Emp #308)"
    })


@app.route("/production/jobs", methods=["GET"])
def get_jobs():
    # Update running jobs slightly to simulate progress
    for job in PRODUCTION_JOBS:
        if job["status"] == "RUNNING" and job["completed_quantity"] < job["target_quantity"]:
            increment = random.randint(0, 3)
            job["completed_quantity"] = min(job["target_quantity"], job["completed_quantity"] + increment)
            if random.random() < 0.05:
                job["scrap_quantity"] += 1

    status_filter = request.args.get("status")
    line_filter = request.args.get("line_id")
    
    jobs = PRODUCTION_JOBS
    if status_filter:
        jobs = [j for j in jobs if j["status"].upper() == status_filter.upper()]
    if line_filter:
        jobs = [j for j in jobs if j["line_id"].upper() == line_filter.upper()]

    return jsonify({
        "total_jobs": len(jobs),
        "jobs": jobs,
        "retrieved_at": datetime.now(timezone.utc).isoformat()
    })


@app.route("/production/jobs", methods=["POST"])
def create_job():
    data = request.get_json(force=True, silent=True) or {}
    
    required_fields = ["product_code", "target_quantity"]
    missing = [f for f in required_fields if f not in data]
    if missing:
        return jsonify({"error": f"Missing required fields: {missing}"}), 400

    new_id = f"JOB-2026-{random.randint(1000, 9999)}"
    new_job = {
        "job_id": new_id,
        "product_code": data["product_code"],
        "description": data.get("description", "Customer Custom Assembly"),
        "batch_number": data.get("batch_number", f"BCH-26-11-X{random.randint(1,9)}"),
        "target_quantity": int(data["target_quantity"]),
        "completed_quantity": 0,
        "scrap_quantity": 0,
        "status": data.get("status", "QUEUED").upper(),
        "line_id": data.get("line_id", "LINE-SMT-01"),
        "priority": data.get("priority", "NORMAL").upper(),
        "operator_id": data.get("operator_id", "UNASSIGNED"),
        "started_at": datetime.now(timezone.utc).isoformat() if data.get("status") == "RUNNING" else None,
        "estimated_completion": data.get("estimated_completion", None),
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    PRODUCTION_JOBS.append(new_job)
    return jsonify({
        "message": "Production job scheduled successfully",
        "job": new_job
    }), 201


@app.route("/quality/metrics", methods=["GET"])
def get_quality_metrics():
    # Return realistic manufacturing quality data
    first_pass_yield = round(96.2 + random.uniform(-0.8, 0.8), 2)
    solder_defect_rate_ppm = round(145 + random.uniform(-15, 25), 1)
    aoi_false_alarm_rate = round(0.42 + random.uniform(-0.05, 0.08), 3)

    return jsonify({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "site_id": SITE_ID,
        "first_pass_yield_percent": first_pass_yield,
        "target_first_pass_yield": 97.0,
        "solder_defect_rate_ppm": solder_defect_rate_ppm,
        "aoi_inspection": {
            "total_inspected_today": 3410 + random.randint(0, 50),
            "pass_count": 3280 + random.randint(0, 40),
            "rework_count": 92 + random.randint(0, 10),
            "scrap_count": 38,
            "false_call_rate_percent": aoi_false_alarm_rate
        },
        "critical_defect_categories": [
            {"defect": "Solder Bridging / Short", "count": 24, "severity": "MEDIUM"},
            {"defect": "Component Tombstoning", "count": 11, "severity": "MEDIUM"},
            {"defect": "Insufficient Solder Paste", "count": 18, "severity": "LOW"},
            {"defect": "Misaligned QFN IC", "count": 6, "severity": "HIGH"},
            {"defect": "Missing Passive Component (0402)", "count": 3, "severity": "HIGH"}
        ],
        "spc_alerts": [] if random.random() > 0.3 else [
            {
                "line_id": "LINE-SMT-01",
                "station": "Reflow Oven Zone 4",
                "metric": "Peak Temperature",
                "value": 248.6,
                "upper_spec_limit": 250.0,
                "warning": "Approaching upper control limit"
            }
        ]
    })


@app.route("/lines", methods=["GET"])
def get_lines():
    return jsonify({
        "plant": SITE_ID,
        "lines": PRODUCTION_LINES
    })


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
