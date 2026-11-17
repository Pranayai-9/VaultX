#!/usr/bin/env python3
"""
BECPL Modbus TCP Industrial Simulator
Simulates a multi-register PLC / RTU controller for BECPL Pune PCB Manufacturing Line.
Registers simulated (Holding Registers, 40001 - 40005):
  - 40001 (Offset 0): Solder Reflow Temperature (°C * 10, e.g., 2350 = 235.0 °C)
  - 40002 (Offset 1): Solder Wave Nitrogen Pressure (PSI * 10, e.g., 620 = 62.0 PSI)
  - 40003 (Offset 2): SMT Line Conveyor Speed (mm/s, e.g., 480)
  - 40004 (Offset 3): Daily Finished PCB Unit Count (e.g., 1420, increments)
  - 40005 (Offset 4): Alarm Status Flag (0 = OK, 1 = Caution, 2 = High Temp Warning)
"""

import sys
import time
import random
import logging
import threading
import asyncio

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("BECPL-ModbusSimulator")

# Simulation baseline state
state = {
    "temperature": 2350,   # 235.0 °C
    "pressure": 620,       # 62.0 PSI
    "speed": 485,          # 485 mm/s
    "product_count": 1420, # 1,420 boards completed
    "alarm_status": 0      # 0 = Normal
}

def update_simulation_values():
    """Periodically perturb simulated sensor values every 2 seconds."""
    logger.info("Simulation sensor update loop started (interval: 2s)")
    while True:
        try:
            # Temperature fluctuates between 228.0°C and 242.0°C
            delta_temp = random.randint(-15, 15)
            state["temperature"] = max(2250, min(2450, state["temperature"] + delta_temp))
            
            # Pressure fluctuates around 60.0 - 64.0 PSI
            delta_press = random.randint(-4, 4)
            state["pressure"] = max(580, min(650, state["pressure"] + delta_press))
            
            # Conveyor speed fluctuates slightly
            delta_speed = random.randint(-5, 5)
            state["speed"] = max(450, min(520, state["speed"] + delta_speed))
            
            # Product count increments occasionally
            if random.random() < 0.35:
                state["product_count"] += 1
                
            # Alarm status triggers on extreme temperature
            if state["temperature"] > 2420:
                state["alarm_status"] = 2  # Warning
            elif state["temperature"] > 2390:
                state["alarm_status"] = 1  # Caution
            else:
                state["alarm_status"] = 0  # Normal

            time.sleep(2.0)
        except Exception as e:
            logger.error(f"Error in sensor update loop: {e}")
            time.sleep(2.0)


async def run_server():
    """Setup and run pymodbus TCP server."""
    try:
        from pymodbus.server import StartAsyncTcpServer
        from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
    except ImportError:
        logger.error("pymodbus not installed. Install with: pip install pymodbus")
        sys.exit(1)

    # Holding registers initialized with 100 registers (0..99)
    # Covering offset 0 (40001) through offset 4 (40005)
    initial_values = [
        state["temperature"],
        state["pressure"],
        state["speed"],
        state["product_count"],
        state["alarm_status"]
    ] + [0] * 95

    datablock = ModbusSequentialDataBlock(0, initial_values)
    slave_context = ModbusSlaveContext(hr=datablock, zero_mode=True)
    server_context = ModbusServerContext(slaves=slave_context, single=True)

    # Background task to sync simulation state to datablock every 2 seconds
    async def sync_registers():
        while True:
            try:
                # Write to both offset 0..4 (address 0) and offset 1..5 (address 1)
                # to accommodate 0-based and 1-based clients
                values = [
                    state["temperature"],
                    state["pressure"],
                    state["speed"],
                    state["product_count"] % 65536,
                    state["alarm_status"]
                ]
                # Function code 3 = Holding Registers
                slave = server_context[0]
                slave.setValues(3, 0, values)
                slave.setValues(3, 1, values)
                logger.debug(
                    f"Updated Registers: Temp={values[0]/10:.1f}C, Press={values[1]/10:.1f}PSI, "
                    f"Speed={values[2]}mm/s, Count={values[3]}, Alarm={values[4]}"
                )
            except Exception as ex:
                logger.warning(f"Register sync exception: {ex}")
            await asyncio.sleep(2.0)

    # Start background updater thread
    threading.Thread(target=update_simulation_values, daemon=True).start()
    
    # Launch async register sync
    asyncio.create_task(sync_registers())

    port = 502
    logger.info(f"Starting BECPL Modbus TCP Server on 0.0.0.0:{port}...")
    try:
        await StartAsyncTcpServer(context=server_context, address=("0.0.0.0", port))
    except PermissionError:
        # If running unprivileged without NET_BIND_SERVICE, fall back to 5020
        alt_port = 5020
        logger.warning(f"Port 502 permission denied, falling back to port {alt_port}")
        await StartAsyncTcpServer(context=server_context, address=("0.0.0.0", alt_port))


if __name__ == "__main__":
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        logger.info("Modbus server shutting down.")
