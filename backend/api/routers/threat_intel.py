"""
backend/api/routers/threat_intel.py — Vulnerability Management, CISA KEV & Threat Intelligence
VaultX Hybrid NIDS for BECPL (Bharat Electronics Components Pvt. Ltd.), Pune
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.api.dependencies import get_current_user, mock_store
from backend.api.schemas import (
    AssetExposureResponse,
    BlocklistEntry,
    JA3CheckRequest,
    JA3CheckResponse,
    KEVRecord,
    SeverityLevel,
    UserProfile,
    VulnerabilityRecord,
)

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence & Vulnerabilities"])


@router.get(
    "/vulnerabilities",
    response_model=List[VulnerabilityRecord],
    summary="List asset vulnerability catalog with CVE and KEV correlation",
)
async def list_vulnerabilities(
    cve_id: Optional[str] = Query(None, description="Filter by CVE ID"),
    severity: Optional[SeverityLevel] = Query(None, description="Filter by severity"),
    asset_id: Optional[str] = Query(None, description="Filter by affected asset ID"),
    kev_only: bool = Query(False, description="Filter to only CISA Known Exploited Vulnerabilities"),
    current_user: UserProfile = Depends(get_current_user),
) -> List[VulnerabilityRecord]:
    """
    Returns inventory of known software and firmware vulnerabilities mapped against BECPL assets.
    """
    results: List[VulnerabilityRecord] = []
    for vuln in mock_store.vulnerabilities.values():
        if cve_id and cve_id.lower() not in vuln["cve_id"].lower():
            continue
        if severity and vuln["severity"] != severity:
            continue
        if asset_id and not any(asset_id.lower() in a.lower() for a in vuln["affected_assets"]):
            continue
        if kev_only and not vuln["in_cisa_kev"]:
            continue
        results.append(VulnerabilityRecord(**vuln))

    return results


@router.get(
    "/vulnerabilities/{cve_id}",
    response_model=VulnerabilityRecord,
    summary="Get CVE details, CVSS rating, and affected manufacturing components",
)
async def get_cve_detail(
    cve_id: str,
    current_user: UserProfile = Depends(get_current_user),
) -> VulnerabilityRecord:
    """Returns specific CVE vulnerability entry with mitigation steps."""
    vuln = mock_store.vulnerabilities.get(cve_id.upper())
    if not vuln:
        for v in mock_store.vulnerabilities.values():
            if v["cve_id"].lower() == cve_id.lower():
                vuln = v
                break

    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability record for '{cve_id}' not found in local catalog.",
        )
    return VulnerabilityRecord(**vuln)


@router.get(
    "/kev",
    response_model=List[KEVRecord],
    summary="Query CISA Known Exploited Vulnerabilities (KEV) catalog",
)
async def get_cisa_kev_catalog(
    search: Optional[str] = Query(None, description="Search term in product name or description"),
    current_user: UserProfile = Depends(get_current_user),
) -> List[KEVRecord]:
    """Returns CISA KEV catalog entries synchronized for vulnerability prioritization."""
    results: List[KEVRecord] = []
    for item in mock_store.kev_catalog:
        if search:
            st = search.lower()
            if st not in item["product"].lower() and st not in item["short_description"].lower() and st not in item["cve_id"].lower():
                continue
        results.append(KEVRecord(**item))
    return results


@router.get(
    "/assets/{asset_id}/exposure",
    response_model=AssetExposureResponse,
    summary="Calculate and return asset exposure rating and vulnerability posture",
)
async def get_asset_exposure_rating(
    asset_id: str,
    current_user: UserProfile = Depends(get_current_user),
) -> AssetExposureResponse:
    """
    Computes exposure score for a specific asset considering network accessibility,
    associated unpatched CVEs, and active threat correlation indicators.
    """
    aid = asset_id.upper()
    matching_vulns = [
        VulnerabilityRecord(**v)
        for v in mock_store.vulnerabilities.values()
        if any(aid in a.upper() for a in v["affected_assets"])
    ]

    # Defaults based on asset ID
    if "CORP-WS-004" in aid:
        return AssetExposureResponse(
            asset_id="CORP-WS-004",
            hostname="corp-ws-finance-04.becpl.internal",
            ip_address="10.10.10.34",
            vlan_id=10,
            zone_name="Corporate IT",
            criticality="medium",
            exposure_rating="critical",
            vulnerabilities=matching_vulns,
            open_ports=[445, 139, 135],
            active_threat_indicators=2,
        )
    elif "ENG-WS-002" in aid:
        return AssetExposureResponse(
            asset_id="ENG-WS-002",
            hostname="eng-ws-firmware-02.becpl.internal",
            ip_address="10.10.20.31",
            vlan_id=20,
            zone_name="Engineering & Firmware",
            criticality="high",
            exposure_rating="high",
            vulnerabilities=matching_vulns,
            open_ports=[22, 8080],
            active_threat_indicators=1,
        )
    elif "MES-SERVER" in aid:
        return AssetExposureResponse(
            asset_id="MES-SERVER",
            hostname="mes-server.becpl.internal",
            ip_address="10.10.30.12",
            vlan_id=30,
            zone_name="Manufacturing OT",
            criticality="critical",
            exposure_rating="high",
            vulnerabilities=matching_vulns,
            open_ports=[5000, 8080],
            active_threat_indicators=1,
        )
    elif "FIRMWARE-STORAGE" in aid:
        return AssetExposureResponse(
            asset_id="FIRMWARE-STORAGE",
            hostname="firmware-storage.becpl.internal",
            ip_address="10.10.20.13",
            vlan_id=20,
            zone_name="Engineering & Firmware",
            criticality="high",
            exposure_rating="medium",
            vulnerabilities=matching_vulns,
            open_ports=[80, 443],
            active_threat_indicators=0,
        )

    # Generic response
    return AssetExposureResponse(
        asset_id=aid,
        hostname=f"{aid.lower()}.becpl.internal",
        ip_address="10.10.10.99",
        vlan_id=10,
        zone_name="Corporate IT",
        criticality="medium",
        exposure_rating="low",
        vulnerabilities=matching_vulns,
        open_ports=[80],
        active_threat_indicators=0,
    )


@router.get(
    "/blocklist",
    response_model=List[BlocklistEntry],
    summary="Get active external threat IP blocklist (C2, Tor exit nodes, scanners)",
)
async def get_threat_ip_blocklist(
    current_user: UserProfile = Depends(get_current_user),
) -> List[BlocklistEntry]:
    """Returns curated local threat intelligence blocklist matching suspicious ingress/egress flows."""
    return [BlocklistEntry(**item) for item in mock_store.ip_blocklist]


@router.post(
    "/check-ja3",
    response_model=JA3CheckResponse,
    summary="Check JA3 / JA3S TLS client fingerprint against threat signatures",
)
async def check_ja3_fingerprint(
    payload: JA3CheckRequest,
    current_user: UserProfile = Depends(get_current_user),
) -> JA3CheckResponse:
    """
    Evaluates TLS client handshake fingerprint to detect unauthorized C2 frameworks (e.g. Cobalt Strike, Sliver)
    without decrypting payload content.
    """
    h = payload.ja3_hash.lower().strip()
    match = mock_store.ja3_signatures.get(h)
    if match:
        return JA3CheckResponse(ja3_hash=h, **match)

    return JA3CheckResponse(
        ja3_hash=h,
        matched_threat=False,
        threat_name=None,
        malware_family=None,
        confidence=0.0,
        first_seen_in_network=True,
        is_whitelisted=False,
    )
