#!/usr/bin/env python3
"""
BECPL External Supplier Integration API Simulation
Simulates supplier-facing purchase orders, order acknowledgement,
and delivery tracking for global component suppliers (Taiwan/China/India).
"""

import os
import random
import uuid
from datetime import datetime, timezone, timedelta
from flask import Flask, jsonify, request

app = Flask(__name__)

SUPPLIER_REGION = os.getenv("SUPPLIER_REGION", "IN-CN-TW")

# In-memory supplier purchase orders
ORDERS = [
    {
        "po_number": "PO-2026-1044",
        "supplier_id": "SUP-TW-001",
        "supplier_name": "TSMC Compound Semiconductor Partner Co.",
        "order_date": "2026-11-10T04:30:00Z",
        "items": [
            {
                "part_number": "IC-STM32F407VGT6",
                "description": "ARM Cortex-M4 Microcontroller LQFP100",
                "ordered_quantity": 5000,
                "unit_price_usd": 6.45
            }
        ],
        "total_value_usd": 32250.00,
        "status": "IN_PRODUCTION",
        "acknowledged": True,
        "acknowledged_at": "2026-11-10T07:15:00Z",
        "estimated_ship_date": "2026-11-28",
        "airway_bill": "CAL-99218204",
        "shipping_carrier": "China Airlines Cargo"
    },
    {
        "po_number": "PO-2026-1045",
        "supplier_id": "SUP-CN-002",
        "supplier_name": "Shenzhen Suntech Multilayer PCB Tech Ltd.",
        "order_date": "2026-11-12T09:00:00Z",
        "items": [
            {
                "part_number": "PCB-RAW-FR4-4L",
                "description": "4-Layer FR-4 Bare Circuit Boards TG150",
                "ordered_quantity": 2500,
                "unit_price_usd": 3.80
            }
        ],
        "total_value_usd": 9500.00,
        "status": "CUSTOMS_CLEARED",
        "acknowledged": True,
        "acknowledged_at": "2026-11-12T10:20:00Z",
        "estimated_ship_date": "2026-11-19",
        "airway_bill": "SF-IN-4820194",
        "shipping_carrier": "SF Express International"
    },
    {
        "po_number": "PO-2026-1046",
        "supplier_id": "SUP-IN-003",
        "supplier_name": "Murata India Electronics Distribution",
        "order_date": "2026-11-17T05:00:00Z",
        "items": [
            {
                "part_number": "CAP-100UF-16V-SMD",
                "description": "Aluminum Electrolytic Capacitor SMD 100uF",
                "ordered_quantity": 30000,
                "unit_price_usd": 0.04
            }
        ],
        "total_value_usd": 1200.00,
        "status": "PENDING_ACKNOWLEDGEMENT",
        "acknowledged": False,
        "acknowledged_at": None,
        "estimated_ship_date": "2026-11-21",
        "airway_bill": None,
        "shipping_carrier": "DTDC Domestic Express"
    }
]


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "BECPL Supplier Integration Gateway",
        "region": SUPPLIER_REGION,
        "version": "1.2.0",
        "endpoints": [
            "/orders (GET)",
            "/orders/acknowledge (POST)",
            "/delivery-status (GET)",
            "/health (GET)"
        ]
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "OK",
        "service": "BECPL-Supplier-Integration",
        "region": SUPPLIER_REGION,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


@app.route("/orders", methods=["GET"])
def get_orders():
    supplier_filter = request.args.get("supplier_id")
    status_filter = request.args.get("status")

    result = ORDERS
    if supplier_filter:
        result = [o for o in result if o["supplier_id"].upper() == supplier_filter.upper()]
    if status_filter:
        result = [o for o in result if o["status"].upper() == status_filter.upper()]

    return jsonify({
        "total_orders": len(result),
        "orders": result,
        "retrieved_at": datetime.now(timezone.utc).isoformat()
    })


@app.route("/orders/acknowledge", methods=["POST"])
def acknowledge_order():
    data = request.get_json(force=True, silent=True) or {}
    po_number = data.get("po_number")
    supplier_id = data.get("supplier_id")
    confirmed_ship_date = data.get("confirmed_ship_date")

    if not po_number:
        return jsonify({"error": "Field 'po_number' is required."}), 400

    order = next((o for o in ORDERS if o["po_number"].upper() == po_number.upper()), None)
    if not order:
        return jsonify({"error": f"PO number '{po_number}' not found."}), 404

    order["acknowledged"] = True
    order["acknowledged_at"] = datetime.now(timezone.utc).isoformat()
    order["status"] = "ACKNOWLEDGED_BY_SUPPLIER"
    if confirmed_ship_date:
        order["estimated_ship_date"] = confirmed_ship_date
    if supplier_id:
        order["supplier_id"] = supplier_id

    return jsonify({
        "message": f"PO {po_number} successfully acknowledged by supplier.",
        "po_number": po_number,
        "status": order["status"],
        "estimated_ship_date": order["estimated_ship_date"],
        "acknowledged_at": order["acknowledged_at"]
    }), 200


@app.route("/delivery-status", methods=["GET"])
def get_delivery_status():
    po_number = request.args.get("po_number")
    awb = request.args.get("airway_bill")

    if po_number:
        matches = [o for o in ORDERS if o["po_number"].upper() == po_number.upper()]
    elif awb:
        matches = [o for o in ORDERS if o.get("airway_bill") and awb.upper() in o["airway_bill"].upper()]
    else:
        matches = ORDERS

    delivery_feed = []
    milestones_cycle = [
        "CUSTOMS_HOLD_JNPT_MUMBAI",
        "IN_TRANSIT_AIR_FREIGHT",
        "OUT_FOR_DELIVERY_PUNE_DOCK",
        "ARRIVED_AT_DESTINATION_PORT"
    ]

    for m in matches:
        delivery_feed.append({
            "po_number": m["po_number"],
            "supplier_name": m["supplier_name"],
            "carrier": m.get("shipping_carrier", "Standard Freight"),
            "airway_bill": m.get("airway_bill", "NOT_ASSIGNED"),
            "shipping_milestone": m["status"] if m["status"] != "PENDING_ACKNOWLEDGEMENT" else "ORDER_CONFIRMED",
            "current_location": "BOM Air Cargo Complex" if "CAL" in str(m.get("airway_bill")) else "Pune Central Delivery Hub",
            "estimated_delivery_date": m.get("estimated_ship_date"),
            "status": m["status"]
        })

    return jsonify({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_tracked": len(delivery_feed),
        "deliveries": delivery_feed
    })


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
