##############################################################################
# becpl_identity_enrichment.zeek
# VaultX — Manufacturing-Aware Hybrid NIDS for BECPL
#
# Purpose:
#   Correlates observed IP addresses with the BECPL asset registry to add
#   identity context to connection events. Zeek cannot determine identity
#   from packets alone — this script bridges that gap by consulting a
#   pre-loaded asset registry JSON (populated at startup from assets.json).
#
# Identity classifications (aligned with VaultX identity model):
#   HUMAN_USER, SERVICE_ACCOUNT, AUTOMATION_WORKLOAD, AI_AGENT,
#   INDUSTRIAL_DEVICE, THIRD_PARTY_IDENTITY, UNKNOWN_IDENTITY
#
# Deploy to: /opt/zeek/share/zeek/site/becpl_identity_enrichment.zeek
##############################################################################

module BECPL_Identity;

##############################################################################
# 1. Exports (types, options, log stream)
##############################################################################

export {
    # Identity classification enum — mirrors VaultX identity model
    type IdentityClass: enum {
        HUMAN_USER,
        SERVICE_ACCOUNT,
        AUTOMATION_WORKLOAD,
        AI_AGENT,
        INDUSTRIAL_DEVICE,
        THIRD_PARTY_IDENTITY,
        UNKNOWN_IDENTITY
    };

    # Asset record (one entry per known asset)
    type AssetRecord: record {
        asset_id:               string;
        hostname:               string;
        vlan:                   count;
        network_segment:        string;
        device_type:            string;
        owner_department:       string;
        criticality:            string;
        identity_class:         IdentityClass;
        vulnerability_exposure: string;
        notes:                  string &default="";
    };

    # Log record written to identity_enrichment.log
    type Info: record {
        ts:                 time              &log;
        uid:                string            &log;
        src_ip:             addr              &log;
        dst_ip:             addr              &log;
        src_asset_id:       string            &log &optional;
        dst_asset_id:       string            &log &optional;
        src_hostname:       string            &log &optional;
        dst_hostname:       string            &log &optional;
        src_identity_class: string            &log &optional;
        dst_identity_class: string            &log &optional;
        src_vlan:           count             &log &optional;
        dst_vlan:           count             &log &optional;
        src_criticality:    string            &log &optional;
        dst_criticality:    string            &log &optional;
        cross_vlan:         bool              &log &default=F;
        anomaly_flags:      vector of string  &log &default=vector();
        sensor_id:          string            &log &default="";
    };

    # Log stream ID
    global log_identity_enrichment: event(rec: Info);

    # In-memory asset registry: IP → AssetRecord
    global asset_registry: table[addr] of AssetRecord = table();

    # Path to the asset registry JSON file (override via redef)
    const asset_registry_file: string =
        "/opt/zeek/share/zeek/site/assets_registry.json" &redef;

    # Sensor ID injected via environment / zeekctl variable
    const sensor_id: string = "SENSOR-UNKNOWN" &redef;

    # Cross-VLAN notice threshold — flag connections that traverse VLANs
    # where no approved path exists (informational; not a final determination)
    const flag_cross_vlan: bool = T &redef;
}

##############################################################################
# 2. Internal helpers
##############################################################################

# Map string → IdentityClass for JSON deserialisation
function str_to_identity_class(s: string): IdentityClass
    {
    if ( s == "HUMAN_USER" )           return HUMAN_USER;
    if ( s == "SERVICE_ACCOUNT" )      return SERVICE_ACCOUNT;
    if ( s == "AUTOMATION_WORKLOAD" )  return AUTOMATION_WORKLOAD;
    if ( s == "AI_AGENT" )             return AI_AGENT;
    if ( s == "INDUSTRIAL_DEVICE" )    return INDUSTRIAL_DEVICE;
    if ( s == "THIRD_PARTY_IDENTITY" ) return THIRD_PARTY_IDENTITY;
    return UNKNOWN_IDENTITY;
    }

function identity_class_to_str(ic: IdentityClass): string
    {
    if ( ic == HUMAN_USER )           return "HUMAN_USER";
    if ( ic == SERVICE_ACCOUNT )      return "SERVICE_ACCOUNT";
    if ( ic == AUTOMATION_WORKLOAD )  return "AUTOMATION_WORKLOAD";
    if ( ic == AI_AGENT )             return "AI_AGENT";
    if ( ic == INDUSTRIAL_DEVICE )    return "INDUSTRIAL_DEVICE";
    if ( ic == THIRD_PARTY_IDENTITY ) return "THIRD_PARTY_IDENTITY";
    return "UNKNOWN_IDENTITY";
    }

##############################################################################
# 3. Load asset registry at startup
#
# Zeek does not have a native JSON parser for arbitrary files; we use the
# Input framework with a custom reader to load a TSV export of assets.json
# generated by a companion script (assets_to_tsv.py) at sensor startup.
# The TSV format: ip  asset_id  hostname  vlan  segment  device_type
#                 dept  criticality  identity_class  vuln_exposure  notes
##############################################################################

type AssetTSVRow: record {
    ip:                     addr    &log;
    asset_id:               string  &log;
    hostname:               string  &log;
    vlan:                   count   &log;
    network_segment:        string  &log;
    device_type:            string  &log;
    owner_department:       string  &log;
    criticality:            string  &log;
    identity_class_str:     string  &log;
    vulnerability_exposure: string  &log;
    notes:                  string  &log;
};

event Input::end_of_data(name: string, source: string)
    {
    # Called when the Input stream finishes loading; nothing extra needed.
    }

event BECPL_Identity::asset_row(description: Input::EventDescription,
                                tpe: Input::Event, r: AssetTSVRow)
    {
    local ar: AssetRecord = [
        $asset_id               = r$asset_id,
        $hostname               = r$hostname,
        $vlan                   = r$vlan,
        $network_segment        = r$network_segment,
        $device_type            = r$device_type,
        $owner_department       = r$owner_department,
        $criticality            = r$criticality,
        $identity_class         = str_to_identity_class(r$identity_class_str),
        $vulnerability_exposure = r$vulnerability_exposure,
        $notes                  = r$notes
    ];
    asset_registry[r$ip] = ar;
    }

event zeek_init()
    {
    # Create log stream
    Log::create_stream(BECPL_Identity::LOG,
        [$columns=Info, $ev=log_identity_enrichment,
         $path="identity_enrichment"]);

    # Load asset TSV (generated from assets.json at sensor boot)
    local tsv_path = "/opt/zeek/share/zeek/site/assets_registry.tsv";
    Input::add_event([
        $source=tsv_path,
        $name="asset_registry_loader",
        $fields=AssetTSVRow,
        $ev=BECPL_Identity::asset_row,
        $mode=Input::REREAD       # reload when file changes (live updates)
    ]);

    Reporter::info(fmt("[BECPL_Identity] Asset registry load initiated from %s",
                       tsv_path));
    }

##############################################################################
# 4. Connection event hook — enrich every connection
##############################################################################

event connection_established(c: connection)
    {
    local rec: Info = [
        $ts     = network_time(),
        $uid    = c$uid,
        $src_ip = c$id$orig_h,
        $dst_ip = c$id$resp_h,
        $sensor_id = sensor_id
    ];

    # Source asset lookup
    if ( c$id$orig_h in asset_registry )
        {
        local src = asset_registry[c$id$orig_h];
        rec$src_asset_id       = src$asset_id;
        rec$src_hostname       = src$hostname;
        rec$src_identity_class = identity_class_to_str(src$identity_class);
        rec$src_vlan           = src$vlan;
        rec$src_criticality    = src$criticality;
        }

    # Destination asset lookup
    if ( c$id$resp_h in asset_registry )
        {
        local dst = asset_registry[c$id$resp_h];
        rec$dst_asset_id       = dst$asset_id;
        rec$dst_hostname       = dst$hostname;
        rec$dst_identity_class = identity_class_to_str(dst$identity_class);
        rec$dst_vlan           = dst$vlan;
        rec$dst_criticality    = dst$criticality;
        }

    # Cross-VLAN flag
    if ( flag_cross_vlan &&
         rec?$src_vlan && rec?$dst_vlan &&
         rec$src_vlan != rec$dst_vlan )
        {
        rec$cross_vlan = T;
        rec$anomaly_flags += "CROSS_VLAN_CONNECTION";
        }

    # Flag unknown source from internal range (potential rogue device)
    if ( c$id$orig_h in Site::local_nets &&
         c$id$orig_h !in asset_registry )
        {
        rec$src_identity_class = "UNKNOWN_IDENTITY";
        rec$anomaly_flags += "UNKNOWN_INTERNAL_SOURCE";
        }

    # Raise a Zeek notice for INDUSTRIAL_DEVICE talking to external hosts
    if ( rec?$src_identity_class &&
         rec$src_identity_class == "INDUSTRIAL_DEVICE" &&
         c$id$resp_h !in Site::local_nets )
        {
        NOTICE([$note=BECPL_Identity::OT_External_Comm,
                $msg=fmt("OT/Industrial device %s (%s) initiated connection to external IP %s — requires investigation",
                         rec$src_hostname, c$id$orig_h, c$id$resp_h),
                $conn=c,
                $identifier=cat(c$id$orig_h)]);
        rec$anomaly_flags += "OT_TO_EXTERNAL";
        }

    # Flag THIRD_PARTY_IDENTITY accessing critical assets
    if ( rec?$src_identity_class &&
         rec$src_identity_class == "THIRD_PARTY_IDENTITY" &&
         rec?$dst_criticality &&
         rec$dst_criticality == "critical" )
        {
        NOTICE([$note=BECPL_Identity::ThirdParty_Critical_Access,
                $msg=fmt("Third-party identity %s (%s) accessing critical asset %s (%s)",
                         rec$src_asset_id, c$id$orig_h,
                         rec$dst_asset_id, c$id$resp_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, "-", c$id$resp_h)]);
        rec$anomaly_flags += "THIRD_PARTY_CRITICAL_ACCESS";
        }

    # Only log if at least one endpoint is known OR there are anomaly flags
    if ( rec?$src_asset_id || rec?$dst_asset_id ||
         |rec$anomaly_flags| > 0 )
        Log::write(BECPL_Identity::LOG, rec);
    }

##############################################################################
# 5. Notice types defined by this module
##############################################################################

export {
    redef enum Notice::Type += {
        OT_External_Comm,          # OT device talking to external IP
        ThirdParty_Critical_Access # Vendor accessing critical asset
    };
}

##############################################################################
# End of becpl_identity_enrichment.zeek
##############################################################################
