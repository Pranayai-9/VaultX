#!/usr/bin/env python3
"""
BECPL Warehouse Management System (WMS) Simulation Server
Simulates inventory tracking, goods receiving, shipment dispatch, and supplier directory
for Bharat Electronics Components Pvt. Ltd. (Pune Warehouse).
"""

import os
import random
import uuid
from datetime import datetime, timezone, timedelta
from flask import Flask, jsonify, request

app = Flask(__name__)

WAREHOUSE_ID = os.getenv("WMS_WAREHOUSE", "BECPL-PUNE-WH1")

# In-memory inventory state
INVENTORY = [
    {
        "sku": "PCB-CTRL-V2",
        "description": "Automotive ECU Controller Board Rev 2.1",
        "category": "FINISHED_GOODS",
        "quantity_on_hand": 1840,
        "quantity_reserved": 350,
        "unit": "PCS",
        "bin_location": "ZONE-A-RACK-03-BIN-12",
        "reorder_level": 500,
        "unit_value_inr": 1450.00
    },
    {
        "sku": "IOT-SNS-TEMP",
        "description": "Industrial Wireless Temperature & Humidity Sensor",
        "category": "FINISHED_GOODS",
        "quantity_on_hand": 920,
        "quantity_reserved": 120,
        "unit": "PCS",
        "bin_location": "ZONE-A-RACK-01-BIN-04",
        "reorder_level": 300,
        "unit_value_inr": 850.00
    },
    {
        "sku": "EMB-BLE-MOD",
        "description": "BLE 5.2 Micro-Module with Antenna",
        "category": "SUB_ASSEMBLIES",
        "quantity_on_hand": 4250,
        "quantity_reserved": 800,
        "unit": "PCS",
        "bin_location": "ZONE-B-RACK-02-BIN-08",
        "reorder_level": 1000,
        "unit_value_inr": 280.00
    },
    {
        "sku": "IC-STM32F407VGT6",
        "description": "ARM Cortex-M4 Microcontroller 168MHz LQFP100",
        "category": "RAW_COMPONENTS",
        "quantity_on_hand": 6500,
        "quantity_reserved": 2500,
        "unit": "PCS",
        "bin_location": "ZONE-C-CLEANROOM-BIN-01",
        "reorder_level": 2000,
        "unit_value_inr": 540.00
    },
    {
        "sku": "CAP-100UF-16V-SMD",
        "description": "Aluminum Electrolytic Capacitor SMD 100uF 16V",
        "category": "PASSIVE_COMPONENTS",
        "quantity_on_hand": 48000,
        "quantity_reserved": 12000,
        "unit": "REEL_UNITS",
        "bin_location": "ZONE-C-REEL-RACK-09",
        "reorder_level": 15000,
        "unit_value_inr": 3.20
    },
    {
        "sku": "RES-10K-0402",
        "description": "Surface Mount Resistor 10k Ohm 0402 1%",
        "category": "PASSIVE_COMPONENTS",
        "quantity_on_hand": 125000,
        "quantity_reserved": 30000,
        "unit": "REEL_UNITS",
        "bin_location": "ZONE-C-REEL-RACK-14",
        "reorder_level": 40000,
        "unit_value_inr": 0.45
    }
]

# In-memory shipments state
SHIPMENTS = [
    {
        "shipment_id": "SHP-2026-0311",
        "customer_name": "Tata Motors CV Division, Pune",
        "items": [
            {"sku": "PCB-CTRL-V2", "quantity": 250}
        ],
        "carrier": "BlueDart Express",
        "tracking_number": "BD99281039IN",
        "status": "DISPATCHED",
        "dispatch_time": "2026-11-17T10:30:00Z",
        "destination": "Pimpri-Chinchwad Works, Pune"
    },
    {
        "shipment_id": "SHP-2026-0312",
        "customer_name": "Bajaj Auto Ltd, Waluj Plant",
        "items": [
            {"sku": "IOT-SNS-TEMP", "quantity": 100}
        ],
        "carrier": "DTDC Express Cargo",
        "tracking_number": "DT77361284IN",
        "status": "IN_TRANSIT",
        "dispatch_time": "2026-11-17T11:45:00Z",
        "destination": "Waluj MIDC, Aurangabad"
    },
    {
        "shipment_id": "SHP-2026-0313",
        "customer_name": "Honeywell Industrial Solutions, Bengaluru",
        "items": [
            {"sku": "EMB-BLE-MOD", "quantity": 500}
        ],
        "carrier": "Delhivery Logistics",
        "tracking_number": "DL12984711IN",
        "status": "PREPARING",
        "dispatch_time": None,
        "destination": "Electronic City, Bengaluru"
    }
]

# In-memory suppliers directory
SUPPLIERS = [
    {
        "supplier_id": "SUP-TW-001",
        "name": "TSMC Compound Semiconductor Partner Co.",
        "location": "Hsinchu Science Park, Taiwan",
        "lead_time_days": 28,
        "primary_supplies": "Semiconductor Silicon & Bare Dies",
        "status": "ACTIVE",
        "currency": "USD",
        "payment_terms": "NET30",
        "quality_rating": 98.7
    },
    {
        "supplier_id": "SUP-CN-002",
        "name": "Shenzhen Suntech Multilayer PCB Tech Ltd.",
        "location": "Baoan District, Shenzhen, China",
        "lead_time_days": 18,
        "primary_supplies": "Bare Multilayer FR-4 Rigid & Flex PCBs",
        "status": "ACTIVE",
        "currency": "USD",
        "payment_terms": "NET45",
        "quality_rating": 95.4
    },
    {
        "supplier_id": "SUP-IN-003",
        "name": "Murata India Electronics Distribution",
        "location": "Manesar, Haryana, India",
        "lead_time_days": 4,
        "primary_supplies": "Passive MLCC Capacitors & Ferrite Beads",
        "status": "ACTIVE",
        "currency": "INR",
        "payment_terms": "NET60",
        "quality_rating": 99.2
    },
    {
        "supplier_id": "SUP-IN-004",
        "name": "Pune Packaging & ESD Enclosures Pvt. Ltd.",
        "location": "Bhosari MIDC, Pune, India",
        "lead_time_days": 2,
        "primary_supplies": "Antistatic ESD Bags, Reels & Master Cartons",
        "status": "ACTIVE",
        "currency": "INR",
        "payment_terms": "NET30",
        "quality_rating": 96.0
    }
]


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "BECPL Warehouse Management System",
        "warehouse": WAREHOUSE_ID,
        "version": "2.1.0",
        "endpoints": [
            "/inventory (GET)",
            "/inventory/receive (POST)",
            "/shipments (GET)",
            "/shipments/dispatch (POST)",
            "/suppliers (GET)"
        ]
    })


@app.route("/inventory", methods=["GET"])
def get_inventory():
    category = request.args.get("category")
    sku = request.args.get("sku")

    items = INVENTORY
    if category:
        items = [i for i in items if i["category"].upper() == category.upper()]
    if sku:
        items = [i for i in items if i["sku"].upper() == sku.upper()]

    total_valuation_inr = sum(i["quantity_on_hand"] * i["unit_value_inr"] for i in INVENTORY)

    return jsonify({
        "warehouse_id": WAREHOUSE_ID,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_sku_count": len(items),
        "total_inventory_valuation_inr": round(total_valuation_inr, 2),
        "inventory": items
    })


@app.route("/inventory/receive", methods=["POST"])
def receive_inventory():
    data = request.get_json(force=True, silent=True) or {}
    sku = data.get("sku")
    quantity = data.get("quantity")
    supplier_id = data.get("supplier_id", "SUP-LOCAL")
    po_number = data.get("po_number", f"PO-2026-{random.randint(1000, 9999)}")

    if not sku or not quantity:
        return jsonify({"error": "Fields 'sku' and 'quantity' are required."}), 400

    try:
        qty_int = int(quantity)
        if qty_int <= 0:
            return jsonify({"error": "Quantity must be positive."}), 400
    except ValueError:
        return jsonify({"error": "Quantity must be an integer."}), 400

    # Locate SKU or add new item
    target_item = next((item for item in INVENTORY if item["sku"].upper() == sku.upper()), None)
    if target_item:
        target_item["quantity_on_hand"] += qty_int
        new_balance = target_item["quantity_on_hand"]
    else:
        new_balance = qty_int
        target_item = {
            "sku": sku.upper(),
            "description": data.get("description", "Incoming Component"),
            "category": data.get("category", "RAW_COMPONENTS"),
            "quantity_on_hand": qty_int,
            "quantity_reserved": 0,
            "unit": data.get("unit", "PCS"),
            "bin_location": data.get("bin_location", "RECEIVING-DOCK-TEMP"),
            "reorder_level": 100,
            "unit_value_inr": float(data.get("unit_value_inr", 50.0))
        }
        INVENTORY.append(target_item)

    receipt_record = {
        "receipt_id": f"GRN-2026-{random.randint(10000, 99999)}",
        "po_number": po_number,
        "supplier_id": supplier_id,
        "sku": sku.upper(),
        "quantity_received": qty_int,
        "current_stock_balance": new_balance,
        "warehouse_location": target_item["bin_location"],
        "received_at": datetime.now(timezone.utc).isoformat(),
        "status": "RECEIVED_AND_STOCKED"
    }

    return jsonify({
        "message": "Goods received note recorded successfully",
        "receipt": receipt_record
    }), 201


@app.route("/shipments", methods=["GET"])
def get_shipments():
    status = request.args.get("status")
    carrier = request.args.get("carrier")

    shipments = SHIPMENTS
    if status:
        shipments = [s for s in shipments if s["status"].upper() == status.upper()]
    if carrier:
        shipments = [s for s in shipments if carrier.lower() in s["carrier"].lower()]

    return jsonify({
        "warehouse_id": WAREHOUSE_ID,
        "total_shipments": len(shipments),
        "shipments": shipments
    })


@app.route("/shipments/dispatch", methods=["POST"])
def dispatch_shipment():
    data = request.get_json(force=True, silent=True) or {}
    customer = data.get("customer_name")
    items = data.get("items", [])
    carrier = data.get("carrier", "BlueDart Express")
    destination = data.get("destination", "Domestic Customer Site")

    if not customer or not items:
        return jsonify({"error": "Fields 'customer_name' and 'items' are required."}), 400

    # Deduct reserved or available quantities
    for item in items:
        sku = item.get("sku")
        qty = int(item.get("quantity", 0))
        inv_item = next((i for i in INVENTORY if i["sku"].upper() == sku.upper()), None)
        if inv_item:
            inv_item["quantity_on_hand"] = max(0, inv_item["quantity_on_hand"] - qty)
            inv_item["quantity_reserved"] = max(0, inv_item["quantity_reserved"] - min(qty, inv_item["quantity_reserved"]))

    new_shipment_id = f"SHP-2026-{random.randint(1000, 9999)}"
    tracking = f"BD{random.randint(10000000, 99999999)}IN" if "BlueDart" in carrier else f"DT{random.randint(10000000, 99999999)}IN"

    dispatch_record = {
        "shipment_id": new_shipment_id,
        "customer_name": customer,
        "items": items,
        "carrier": carrier,
        "tracking_number": tracking,
        "status": "DISPATCHED",
        "dispatch_time": datetime.now(timezone.utc).isoformat(),
        "destination": destination
    }

    SHIPMENTS.append(dispatch_record)

    return jsonify({
        "message": "Outbound shipment dispatched successfully",
        "shipment": dispatch_record
    }), 201


@app.route("/suppliers", methods=["GET"])
def get_suppliers():
    status = request.args.get("status")
    sups = SUPPLIERS
    if status:
        sups = [s for s in sups if s["status"].upper() == status.upper()]

    return jsonify({
        "total_suppliers": len(sups),
        "suppliers": sups
    })


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
