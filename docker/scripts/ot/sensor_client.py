#!/usr/bin/env python3
"""
BECPL Industrial Sensor Telemetry Client
Connects to simulated Modbus TCP PLC/simulator, polls operational telemetry,
and outputs structured JSON to stdout for NIDS/monitoring ingestion.
"""

import os
import sys
import time
import json
import logging
from datetime import datetime, timezone

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("SensorClient")

MODBUS_HOST = os.getenv("MODBUS_HOST", "172.20.30.14")
MODBUS_PORT = int(os.getenv("MODBUS_PORT", 502))
SENSOR_ID = os.getenv("SENSOR_ID", "SENSOR-001")
SENSOR_TYPE = os.getenv("SENSOR_TYPE", "multisensor-telemetry")
SENSOR_LOCATION = os.getenv("SENSOR_LOCATION", "PCB-LINE-1-ZONE-A")
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", 5.0))


def create_modbus_client(host, port):
    """Instantiate Modbus TCP client supporting pymodbus v2 and v3."""
    try:
        from pymodbus.client import ModbusTcpClient
        return ModbusTcpClient(host=host, port=port)
    except ImportError:
        try:
            from pymodbus.client.sync import ModbusTcpClient
            return ModbusTcpClient(host=host, port=port)
        except ImportError:
            logger.error("pymodbus not installed. Install with: pip install pymodbus")
            sys.exit(1)


def read_holding_registers(client, address, count):
    """Read holding registers across pymodbus version differences."""
    try:
        # pymodbus v3 uses slave or unit
        try:
            rr = client.read_holding_registers(address, count=count, slave=1)
        except TypeError:
            rr = client.read_holding_registers(address, count, unit=1)

        if rr.isError():
            # Try 0-based address
            try:
                rr = client.read_holding_registers(0, count=count, slave=1)
            except TypeError:
                rr = client.read_holding_registers(0, count, unit=1)
                
        if not rr.isError() and hasattr(rr, "registers") and len(rr.registers) >= count:
            return rr.registers
        return None
    except Exception as e:
        logger.debug(f"Modbus read error: {e}")
        return None


def main():
    logger.info(
        f"Starting {SENSOR_ID} ({SENSOR_TYPE}) at {SENSOR_LOCATION}. Target: {MODBUS_HOST}:{MODBUS_PORT}"
    )

    client = create_modbus_client(MODBUS_HOST, MODBUS_PORT)
    retry_delay = 3

    while True:
        connected = False
        try:
            if not client.connected:
                connected = client.connect()
                if connected:
                    logger.info(f"Connected to Modbus PLC at {MODBUS_HOST}:{MODBUS_PORT}")
                else:
                    logger.warning(
                        f"Connection to Modbus PLC failed, retrying in {retry_delay}s..."
                    )
                    time.sleep(retry_delay)
                    continue

            # Read 5 holding registers:
            # 0: Temperature (C * 10)
            # 1: Pressure (PSI * 10)
            # 2: Speed (mm/s)
            # 3: Count
            # 4: Alarm status
            regs = read_holding_registers(client, 0, 5)

            if regs is not None and len(regs) >= 5:
                raw_temp, raw_press, raw_speed, count, alarm = regs[:5]
                temp_c = round(raw_temp / 10.0, 2)
                press_psi = round(raw_press / 10.0, 2)

                alarm_labels = {0: "NORMAL", 1: "CAUTION_HIGH_TEMP", 2: "ALARM_OVERTEMP"}
                alarm_str = alarm_labels.get(alarm, f"UNKNOWN_{alarm}")

                telemetry = {
                    "event_type": "industrial_telemetry",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "sensor_id": SENSOR_ID,
                    "sensor_type": SENSOR_TYPE,
                    "location": SENSOR_LOCATION,
                    "modbus_source": f"{MODBUS_HOST}:{MODBUS_PORT}",
                    "readings": {
                        "temperature_celsius": temp_c,
                        "pressure_psi": press_psi,
                        "conveyor_speed_mms": raw_speed,
                        "finished_product_count": count,
                        "alarm_code": alarm,
                        "alarm_status": alarm_str
                    },
                    "quality_status": "GOOD" if alarm == 0 else "WARNING"
                }

                # Output JSON to stdout (standard telemetry pattern for log collector)
                print(json.dumps(telemetry), flush=True)
            else:
                logger.warning("Empty or error response reading Modbus registers")

        except Exception as ex:
            logger.error(f"Unexpected exception during sensor poll: {ex}")
            try:
                client.close()
            except Exception:
                pass

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Sensor client terminated by user.")
