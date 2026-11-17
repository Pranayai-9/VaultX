##############################################################################
# becpl_ot_monitor.zeek
# VaultX — Manufacturing-Aware Hybrid NIDS for BECPL
#
# Purpose:
#   Custom Zeek script for OT / Manufacturing network monitoring (VLAN 30).
#   - Monitors Modbus TCP traffic on port 502.
#   - Logs Modbus function codes, register access ranges, and transaction rates.
#   - Detects unauthorized access from non-approved IPs to Modbus servers.
#   - Detects burst / unusually high read/write transaction rates.
#   - Detects Modbus connections outside authorized business/production hours.
#   - Generates structured notices for anomaly correlation by the NIDS engine.
#
# Deploy to: /opt/zeek/share/zeek/site/becpl_ot_monitor.zeek
##############################################################################

module BECPL_OT;

export {
    redef enum Notice::Type += {
        Unauthorized_Modbus_Client,     # Source IP not permitted to talk Modbus
        Modbus_High_Transaction_Rate,   # Suspicious polling/write flood
        Modbus_Off_Hours_Activity,      # Modbus command outside production window
        Modbus_Dangerous_Function_Code, # Firmware reload, diagnostic, or coil forced
        Modbus_Write_To_Safety_System  # Write command directed at emergency/safety PLC
    };

    # Custom log record for OT / Modbus transactions
    type ModbusLogRecord: record {
        ts:              time    &log;
        uid:             string  &log;
        id:              conn_id &log;
        unit_id:         count   &log &optional;
        function_code:   count   &log &optional;
        function_name:   string  &log &optional;
        register_addr:   count   &log &optional;
        register_count:  count   &log &optional;
        is_write:        bool    &log &default=F;
        is_authorized:   bool    &log &default=T;
        client_segment:  string  &log &default="UNKNOWN";
        server_segment:  string  &log &default="OT_VLAN30";
        sensor_id:       string  &log &default="SENSOR-OT-01";
    };

    global log_becpl_modbus: event(rec: ModbusLogRecord);

    # Approved Modbus Master / Client IP whitelist (HMIs, Engineering SCADA, Historian)
    # 172.20.30.10: Primary SCADA Master / HMI 01
    # 172.20.30.11: Secondary HMI / SMT Line Controller
    # 172.20.20.15: Engineering Workstation (Authorized diagnostic master)
    # 172.20.30.50: MES Gateway node
    const approved_modbus_clients: set[addr] = {
        172.20.30.10,
        172.20.30.11,
        172.20.20.15,
        172.20.30.50
    } &redef;

    # Critical Safety PLCs (Emergency stop, reflow oven thermal cutoff)
    const safety_plc_ips: set[addr] = {
        172.20.30.25,
        172.20.30.26
    } &redef;

    # Rate limiting thresholds (transactions per 10-second window)
    const max_rate_per_interval: count = 120 &redef; # > 12 commands/sec is abnormal
    const rate_check_interval: interval = 10 secs &redef;

    # Shift / Production operational window (07:00 to 20:00 IST / local time)
    # 0 = Sunday, 1 = Monday ... 6 = Saturday
    const business_hour_start: count = 7 &redef;
    const business_hour_end: count = 20 &redef;

    const sensor_id: string = "SENSOR-OT-01" &redef;
}

# State tracking for rate detection: [src_ip, dst_ip] -> count
global transaction_counts: table[addr, addr] of count &create_expire=rate_check_interval;

function get_modbus_func_name(fc: count): string
    {
    if ( fc == 1 ) return "Read Coils";
    if ( fc == 2 ) return "Read Discrete Inputs";
    if ( fc == 3 ) return "Read Holding Registers";
    if ( fc == 4 ) return "Read Input Registers";
    if ( fc == 5 ) return "Write Single Coil";
    if ( fc == 6 ) return "Write Single Register";
    if ( fc == 15 ) return "Write Multiple Coils";
    if ( fc == 16 ) return "Write Multiple Registers";
    if ( fc == 43 ) return "Read Device Identification";
    if ( fc == 8 ) return "Diagnostics";
    return fmt("Unknown_FC_%d", fc);
    }

function is_write_function(fc: count): bool
    {
    return (fc == 5 || fc == 6 || fc == 15 || fc == 16);
    }

event zeek_init()
    {
    Log::create_stream(BECPL_OT::LOG,
        [$columns=ModbusLogRecord, $ev=log_becpl_modbus, $path="becpl_modbus"]);
    Reporter::info("[BECPL_OT] Modbus OT Monitor initialized for BECPL VLAN 30.");
    }

# Track TCP connections destined for Modbus port 502
event connection_established(c: connection)
    {
    if ( c$id$resp_p != 502/tcp )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # 1. Check IP Authorization
    if ( src !in approved_modbus_clients )
        {
        NOTICE([
            $note=BECPL_OT::Unauthorized_Modbus_Client,
            $msg=fmt("Modbus connection to PLC %s from unauthorized IP %s (Port 502)", dst, src),
            $conn=c,
            $identifier=cat(src, dst, "502")
        ]);
        }

    # 2. Check Business Hours / Operational Shift
    local current_time = network_time();
    # Approximate hour extraction
    # Using epoch modulo math for hours since epoch (assuming UTC+5:30 IST)
    local local_seconds = time_to_double(current_time) + (5.5 * 3600);
    local seconds_in_day = double_to_count(local_seconds) % 86400;
    local hour_of_day = seconds_in_day / 3600;

    if ( hour_of_day < business_hour_start || hour_of_day >= business_hour_end )
        {
        NOTICE([
            $note=BECPL_OT::Modbus_Off_Hours_Activity,
            $msg=fmt("Modbus connection established during off-hours (%02d:00 IST) from %s to %s",
                     hour_of_day, src, dst),
            $conn=c,
            $identifier=cat(src, dst, "off-hours")
        ]);
        }
    }

# Deep Modbus parsing if the standard Zeek Modbus protocol analyzer is active
event modbus_message(c: connection, is_orig: bool, func: count)
    {
    if ( !is_orig )
        return; # Only examine client requests

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # Rate tracking
    if ( [src, dst] !in transaction_counts )
        transaction_counts[src, dst] = 0;
    transaction_counts[src, dst] += 1;

    if ( transaction_counts[src, dst] > max_rate_per_interval )
        {
        NOTICE([
            $note=BECPL_OT::Modbus_High_Transaction_Rate,
            $msg=fmt("High Modbus transaction rate: %d msgs in %s from %s to %s",
                     transaction_counts[src, dst], rate_check_interval, src, dst),
            $conn=c,
            $identifier=cat(src, dst, "rate")
        ]);
        }

    local is_write = is_write_function(func);

    # Safety PLC check
    if ( is_write && dst in safety_plc_ips )
        {
        NOTICE([
            $note=BECPL_OT::Modbus_Write_To_Safety_System,
            $msg=fmt("Modbus write command (FC: %d - %s) targeting Safety/Critical PLC %s from %s",
                     func, get_modbus_func_name(func), dst, src),
            $conn=c,
            $identifier=cat(src, dst, "safety_write")
        ]);
        }

    # Dangerous function codes (e.g. diagnostics 0x08, firmware update commands)
    if ( func == 8 || func > 16 )
        {
        NOTICE([
            $note=BECPL_OT::Modbus_Dangerous_Function_Code,
            $msg=fmt("Potentially hazardous or diagnostic Modbus FC %d (%s) from %s to %s",
                     func, get_modbus_func_name(func), src, dst),
            $conn=c,
            $identifier=cat(src, dst, cat(func))
        ]);
        }

    local rec: ModbusLogRecord = [
        $ts             = network_time(),
        $uid            = c$uid,
        $id             = c$id,
        $function_code  = func,
        $function_name  = get_modbus_func_name(func),
        $is_write       = is_write,
        $is_authorized  = (src in approved_modbus_clients),
        $client_segment = (src in Site::local_nets) ? "BECPL_INTERNAL" : "EXTERNAL",
        $server_segment = "OT_VLAN30",
        $sensor_id      = sensor_id
    ];

    Log::write(BECPL_OT::LOG, rec);
    }
