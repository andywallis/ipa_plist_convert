#!/usr/bin/env python3
"""
ipa_plist_convert_and_analyse.py

Convert an iOS plist (from .ipa or standalone .plist) to XML and print a
security-focused summary with potential issues.

Examples:
  python ipa_plist_convert_and_analyse.py app.ipa
  python ipa_plist_convert_and_analyse.py app.ipa -o out/Info.plist.xml
  python ipa_plist_convert_and_analyse.py Info.plist
  python ipa_plist_convert_and_analyse.py Info.plist --json

Notes:
- No third-party deps; uses Python stdlib (plistlib/zipfile).
- If the IPA has multiple .app bundles, use --index to pick one or omit to analyse all.
"""

import argparse
import json
import os
import plistlib
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

# ---------- Core I/O ----------

def convert_plist_bytes_to_xml(plist_bytes: bytes) -> bytes:
    data = plistlib.loads(plist_bytes)
    return plistlib.dumps(data, fmt=plistlib.FMT_XML, sort_keys=False)

def find_info_plists_in_ipa(zip_path: str) -> List[Tuple[str, str]]:
    """Return list of (app_dir, info_plist_zip_path) found inside the IPA."""
    results: List[Tuple[str, str]] = []
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for zi in zf.infolist():
            parts = Path(zi.filename).parts
            if len(parts) >= 3 and parts[0] == "Payload" and parts[-1] == "Info.plist":
                if any(p.endswith(".app") for p in parts):
                    app_dir = next((p for p in parts if p.endswith(".app")), None)
                    results.append((app_dir or "App.app", zi.filename))
    return results

def read_zip_member_bytes(zip_path: str, member: str) -> bytes:
    with zipfile.ZipFile(zip_path, 'r') as zf:
        with zf.open(member, 'r') as f:
            return f.read()

def default_output_path_for_ipa(ipa_path: str, app_dir: str) -> Path:
    base = Path(ipa_path).with_suffix('')
    app_name = app_dir[:-4] if app_dir.endswith('.app') else "App"
    return base.parent / f"{base.name}_{app_name}_Info.plist.xml"

def default_output_path_for_plist(plist_path: str) -> Path:
    p = Path(plist_path)
    return p.with_suffix(p.suffix + ".xml") if p.suffix != ".xml" else p

def ensure_parent_dir(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)

# ---------- Analysis ----------

def get(d: Dict[str, Any], *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def analyse_info_plist(info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pull out commonly useful fields and flag potential issues
    (best-effort heuristics based solely on Info.plist).
    """
    out: Dict[str, Any] = {}

    # Basic app metadata
    out["bundle_identifier"] = info.get("CFBundleIdentifier")
    out["bundle_name"] = info.get("CFBundleName") or info.get("CFBundleDisplayName")
    out["version"] = info.get("CFBundleShortVersionString")
    out["build"] = info.get("CFBundleVersion")
    out["minimum_ios_version"] = info.get("MinimumOSVersion")
    out["required_device_capabilities"] = info.get("UIRequiredDeviceCapabilities")
    out["supports_ipad"] = bool(info.get("UIDeviceFamily")) and (2 in info.get("UIDeviceFamily", []))
    out["background_modes"] = info.get("UIBackgroundModes")
    out["supports_document_browser"] = info.get("UISupportsDocumentBrowser")
    out["supports_opening_documents_in_place"] = info.get("LSSupportsOpeningDocumentsInPlace")
    out["file_sharing_enabled"] = info.get("UIFileSharingEnabled")
    out["requires_full_screen"] = info.get("UIRequiresFullScreen")
    out["application_queries_schemes_count"] = len(info.get("LSApplicationQueriesSchemes", []) or [])

    # URL schemes
    url_types = info.get("CFBundleURLTypes") or []
    schemes: List[str] = []
    for item in url_types:
        for s in item.get("CFBundleURLSchemes", []) or []:
            schemes.append(s)
    out["url_schemes"] = schemes

    # App Transport Security (ATS)
    ats = info.get("NSAppTransportSecurity") or {}
    out["ats_raw"] = ats or None  # include raw for inspection

    # Privacy usage strings present (informational only)
    privacy_keys = [k for k in info.keys() if k.endswith("UsageDescription")]
    out["privacy_usage_descriptions"] = {k: bool(info.get(k)) for k in sorted(privacy_keys)}

    # Potential issues (heuristic; not definitive)
    issues: List[str] = []

    # ATS weaknesses
    if ats:
        if ats.get("NSAllowsArbitraryLoads") is True:
            issues.append("ATS disabled globally (NSAllowsArbitraryLoads=true). Prefer HTTPS or scoped exceptions.")
        if ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
            issues.append("ATS disabled for web views (NSAllowsArbitraryLoadsInWebContent=true). Scope this if possible.")
        if ats.get("NSAllowsLocalNetworking") is True:
            issues.append("ATS allows local networking. Ensure this is required and threat-modelled.")
        # Per-domain exceptions
        ex = ats.get("NSExceptionDomains") or {}
        for domain, exv in ex.items():
            if exv.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                if exv.get("NSIncludesSubdomains") is True:
                    issues.append(f"ATS exception: HTTP allowed for {domain} and subdomains.")
                else:
                    issues.append(f"ATS exception: HTTP allowed for {domain}.")
            if exv.get("NSPinnedDomains"):
                # Not an issue; could be good. Just report separately if desired.
                pass

    # File sharing / document handling
    if info.get("UIFileSharingEnabled") is True:
        issues.append("File sharing enabled (UIFileSharingEnabled=true). App documents may be accessible over iTunes/Finder.")
    if info.get("LSSupportsOpeningDocumentsInPlace") is True:
        issues.append("Opening documents in place enabled. Ensure safe handling of untrusted files/urls.")

    # Custom URL schemes
    if schemes:
        issues.append(
            "Custom URL schemes registered. Ensure uniqueness and consider Universal Links to reduce scheme hijacking."
        )

    # Background modes
    bg = info.get("UIBackgroundModes") or []
    suspicious_bg = {"location", "voip", "external-accessory"}
    if any(x in suspicious_bg for x in bg):
        issues.append(f"Background modes include {sorted(set(bg) & suspicious_bg)}. Validate necessity.")

    # Query schemes scale
    if out["application_queries_schemes_count"] and out["application_queries_schemes_count"] > 50:
        issues.append(f"Large LSApplicationQueriesSchemes list ({out['application_queries_schemes_count']}). "
                      "Broad canOpenURL enumeration may be excessive.")

    # Deprecated / legacy flags
    if info.get("UIRequiresPersistentWiFi") is True:
        issues.append("UIRequiresPersistentWiFi is deprecated. Remove if not needed.")

    out["issues"] = issues
    return out

# ---------- Command handlers ----------

def process_plist_bytes(plist_bytes: bytes,
                        xml_out_path: Path | None,
                        print_json: bool,
                        label: str):
    # Convert to XML
    xml_bytes = convert_plist_bytes_to_xml(plist_bytes)
    if xml_out_path:
        ensure_parent_dir(xml_out_path)
        with open(xml_out_path, "wb") as f:
            f.write(xml_bytes)
    info = plistlib.loads(plist_bytes)
    summary = analyse_info_plist(info)

    # Print summary
    if print_json:
        payload = {
            "target": label,
            "xml_output": str(xml_out_path) if xml_out_path else None,
            "summary": summary,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"\n=== {label} ===")
        if xml_out_path:
            print(f"[+] XML written: {xml_out_path}")
        print(f"Bundle ID:         {summary.get('bundle_identifier')}")
        print(f"Name:              {summary.get('bundle_name')}")
        print(f"Version (build):   {summary.get('version')} ({summary.get('build')})")
        print(f"Minimum iOS:       {summary.get('minimum_ios_version')}")
        print(f"Device families:   {summary.get('supports_ipad') and 'iPhone + iPad' or 'iPhone-only/unspecified'}")
        print(f"Background modes:  {summary.get('background_modes')}")
        print(f"File sharing:      {summary.get('file_sharing_enabled')}")
        print(f"Open in place:     {summary.get('supports_opening_documents_in_place')}")
        print(f"URL schemes ({len(summary.get('url_schemes', []))}): {summary.get('url_schemes')}")
        print(f"LSAppQueries count:{summary.get('application_queries_schemes_count')}")
        ats = summary.get("ats_raw")
        print(f"ATS present:       {bool(ats)}")
        if ats:
            print(f"  NSAllowsArbitraryLoads:              {get(ats, 'NSAllowsArbitraryLoads')}")
            print(f"  NSAllowsArbitraryLoadsInWebContent:  {get(ats, 'NSAllowsArbitraryLoadsInWebContent')}")
            print(f"  NSAllowsLocalNetworking:             {get(ats, 'NSAllowsLocalNetworking')}")
            ex = get(ats, 'NSExceptionDomains') or {}
            if ex:
                print("  NSExceptionDomains:")
                for domain, cfg in ex.items():
                    print(f"    - {domain}: {cfg}")
        priv = summary.get("privacy_usage_descriptions") or {}
        if priv:
            present = [k for k, v in priv.items() if v]
            print(f"Privacy usage strings present ({len(present)}):")
            for k in present:
                print(f"  - {k}")

        issues = summary.get("issues") or []
        if issues:
            print("\nPotential issues:")
            for i, issue in enumerate(issues, 1):
                print(f"  {i}. {issue}")
        else:
            print("\nPotential issues: none detected (heuristic)")

def convert_and_analyse_plist_file(plist_path: str, output: str | None, print_json: bool):
    with open(plist_path, "rb") as f:
        plist_bytes = f.read()
    out_path = Path(output) if output else default_output_path_for_plist(plist_path)
    process_plist_bytes(plist_bytes, out_path, print_json, label=Path(plist_path).name)

def convert_and_analyse_ipa(ipa_path: str, output: str | None, index: int | None, print_json: bool):
    infos = find_info_plists_in_ipa(ipa_path)
    if not infos:
        print(f"[!] No Info.plist found under Payload/*.app in '{ipa_path}'.", file=sys.stderr)
        sys.exit(3)

    # If multiple .app bundles exist, allow picking one
    selected = infos
    if index is not None:
        if index < 0 or index >= len(infos):
            print(f"[!] Index {index} out of range (found {len(infos)} app(s)).", file=sys.stderr)
            sys.exit(4)
        selected = [infos[index]]

    for app_dir, plist_zip_path in selected:
        raw = read_zip_member_bytes(ipa_path, plist_zip_path)
        # If output is a directory, write separate files; otherwise craft default
        if output:
            out_path = Path(output)
            if out_path.is_dir():
                out_file = out_path / f"{Path(ipa_path).stem}_{app_dir[:-4]}_Info.plist.xml"
            else:
                # If user passed a file path but we have multiple plists, avoid clobbering
                if len(selected) > 1:
                    out_file = out_path.parent / f"{out_path.stem}_{app_dir[:-4]}{out_path.suffix or '.xml'}"
                else:
                    out_file = out_path
        else:
            out_file = default_output_path_for_ipa(ipa_path, app_dir)

        label = f"{Path(ipa_path).name}::{app_dir}"
        process_plist_bytes(raw, out_file, print_json, label=label)

# ---------- CLI ----------

def main():
    ap = argparse.ArgumentParser(description="Convert iOS Info.plist to XML and print a security-focused summary.")
    ap.add_argument("input", help="Path to .ipa or .plist")
    ap.add_argument("-o", "--output",
                    help="Output file (or directory if converting multiple). Defaults near the input.")
    ap.add_argument("--index", type=int,
                    help="If IPA contains multiple .app bundles, analyse only the one at this index (0-based).")
    ap.add_argument("--json", action="store_true",
                    help="Emit JSON instead of human-readable text (summary + where XML was written).")
    args = ap.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[!] Input does not exist: {in_path}", file=sys.stderr)
        sys.exit(1)

    try:
        if in_path.suffix.lower() == ".ipa" or _looks_like_zip(str(in_path)):
            convert_and_analyse_ipa(str(in_path), args.output, args.index, args.json)
        else:
            convert_and_analyse_plist_file(str(in_path), args.output, args.json)
    except zipfile.BadZipFile:
        # Not a ZIP—treat as plist
        convert_and_analyse_plist_file(str(in_path), args.output, args.json)

def _looks_like_zip(path: str) -> bool:
    try:
        with zipfile.ZipFile(path, 'r'):
            return True
    except zipfile.BadZipFile:
        return False

if __name__ == "__main__":
    main()
