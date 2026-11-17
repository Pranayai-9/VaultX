##############################################################################
# becpl_lateral_movement.zeek
# VaultX — Manufacturing-Aware Hybrid NIDS for BECPL
#
# Purpose:
#   Custom Zeek script for detecting lateral movement and internal host scanning.
#   - Tracks connection counts per source IP per destination subnet over time.
#   - Raises a notice when a single internal IP connects to more than N distinct
#     hosts within M minutes (configurable horizontal reconnaissance threshold).
#   - Detects rapid sequential connections across multiple VLANs/subnets.
#   - Logs structured lateral movement telemetry for correlation with endpoint events.
#
# Deploy to: /opt/zeek/share/zeek/site/becpl_lateral_movement.zeek
##############################################################################

module BECPL_Lateral;

export {
    redef enum Notice::Type += {
        Lateral_Movement_Suspected,      # Host contacted > N targets within M minutes
        Cross_Subnet_Spread,             # Host reaching across > 2 internal subnets rapidly
        Admin_Service_Lateral_Sweep      # Port 22/3389/445 sweep from non-admin workstation
    };

    # Log record for lateral movement tracking
    type LateralTrackRecord: record {
        ts:                 time    &log;
        src_ip:             addr    &log;
        dst_count:          count   &log;
        distinct_subnets:   count   &log;
        observed_services:  set[port] &log;
        alert_raised:       bool    &log &default=F;
        window_minutes:     count   &log;
        sensor_id:          string  &log &default="SENSOR-CORP-01";
    };

    global log_becpl_lateral: event(rec: LateralTrackRecord);

    # Thresholds
    # Max distinct destinations within tracking_window before alerting
    const host_threshold: count = 8 &redef;
    # Window duration
    const tracking_window: interval = 3 mins &redef;
    # Multi-subnet threshold (e.g. hitting >= 3 different /24 subnets)
    const subnet_threshold: count = 3 &redef;

    # Sensitive administration / lateral movement ports
    const sensitive_ports: set[port] = {
        22/tcp,    # SSH
        3389/tcp,  # RDP
        445/tcp,   # SMB
        135/tcp,   # RPC endpoint mapper
        5985/tcp,  # WinRM HTTP
        5986/tcp   # WinRM HTTPS
    } &redef;

    # Authorized IT admin jump hosts / vulnerability scanners (whitelisted)
    const admin_jump_hosts: set[addr] = {
        172.20.70.10,  # SecOps Admin Box
        172.20.70.15,  # Bastion Jump Server
        172.20.10.254  # Central Network Monitor
    } &redef;

    const sensor_id: string = "SENSOR-CORP-01" &redef;
}

# Per-source IP tracking state
type SourceTracker: record {
    targets:        set[addr];
    target_subnets: set[subnet];
    services:       set[port];
    first_seen:     time;
    last_alert:     time &default=double_to_time(0.0);
};

global active_trackers: table[addr] of SourceTracker &create_expire=tracking_window;

event zeek_init()
    {
    Log::create_stream(BECPL_Lateral::LOG,
        [$columns=LateralTrackRecord, $ev=log_becpl_lateral, $path="becpl_lateral"]);
    Reporter::info("[BECPL_Lateral] Lateral movement detection module initialized.");
    }

event connection_established(c: connection)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local dport = c$id$resp_p;

    # Only inspect internal-to-internal traffic
    if ( src !in Site::local_nets || dst !in Site::local_nets )
        return;

    # Skip authorized admin hosts
    if ( src in admin_jump_hosts )
        return;

    # Ignore self-connections or broadcast/multicast
    if ( src == dst )
        return;

    # Initialize tracker if new
    if ( src !in active_trackers )
        {
        local new_tracker: SourceTracker = [
            $targets        = set(),
            $target_subnets = set(),
            $services       = set(),
            $first_seen     = network_time()
        ];
        active_trackers[src] = new_tracker;
        }

    local tracker = active_trackers[src];
    add tracker$targets[dst];
    add tracker$services[dport];

    # Calculate /24 subnet for destination
    local dst_sub = to_subnet(fmt("%s/24", dst));
    add tracker$target_subnets[dst_sub];

    local num_targets = |tracker$targets|;
    local num_subnets = |tracker$target_subnets|;
    local now = network_time();

    # 1. Distinct Host Count Threshold Trigger
    if ( num_targets >= host_threshold && (now - tracker$last_alert > 2 mins) )
        {
        tracker$last_alert = now;

        NOTICE([
            $note=BECPL_Lateral::Lateral_Movement_Suspected,
            $msg=fmt("Lateral movement alert: Internal host %s connected to %d distinct hosts across %d subnets within %s",
                     src, num_targets, num_subnets, tracking_window),
            $conn=c,
            $identifier=cat(src, "lateral_host_threshold")
        ]);

        local rec: LateralTrackRecord = [
            $ts                 = now,
            $src_ip             = src,
            $dst_count          = num_targets,
            $distinct_subnets   = num_subnets,
            $observed_services  = tracker$services,
            $alert_raised       = T,
            $window_minutes     = 3,
            $sensor_id          = sensor_id
        ];
        Log::write(BECPL_Lateral::LOG, rec);
        }

    # 2. Cross-Subnet Spread Trigger
    if ( num_subnets >= subnet_threshold && (now - tracker$last_alert > 2 mins) )
        {
        tracker$last_alert = now;

        NOTICE([
            $note=BECPL_Lateral::Cross_Subnet_Spread,
            $msg=fmt("Multi-VLAN reconnaissance: Host %s contacting %d different /24 subnets rapidly",
                     src, num_subnets),
            $conn=c,
            $identifier=cat(src, "cross_subnet")
        ]);
        }

    # 3. Sensitive Admin Port Probing Trigger (RDP, SSH, SMB across >= 3 internal hosts)
    if ( dport in sensitive_ports && num_targets >= 3 )
        {
        NOTICE([
            $note=BECPL_Lateral::Admin_Service_Lateral_Sweep,
            $msg=fmt("Host %s performing lateral sweep targeting admin service %s across multiple hosts (%d targets)",
                     src, dport, num_targets),
            $conn=c,
            $identifier=cat(src, cat(dport), "admin_sweep")
        ]);
        }
    }
