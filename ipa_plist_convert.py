#!/usr/bin/env python3
"""
ipa_plist_convert.py

Convert an iOS plist to XML. Works with:
  1) A .plist file path (binary or XML) -> writes XML
  2) An .ipa file path -> extracts Payload/*/*.app/Info.plist and writes XML

Usage:
  python ipa_plist_convert.py path/to/app.ipa -o out/Info.plist.xml
  python ipa_plist_convert.py path/to/Info.plist -o out/Info.plist.xml

If -o/--output is omitted, a sensible filename is chosen next to the input.
"""

import argparse
import os
import sys
import plistlib
import zipfile
from io import BytesIO
from pathlib import Path

def convert_plist_bytes_to_xml(plist_bytes: bytes) -> bytes:
    # plistlib handles both binary and XML transparently
    data = plistlib.loads(plist_bytes)
    # Dump as pretty XML
    return plistlib.dumps(data, fmt=plistlib.FMT_XML, sort_keys=False)

def find_info_plists_in_ipa(zip_path: str):
    """Return list of (app_dir, info_plist_zip_path) found inside the IPA."""
    results = []
    with zipfile.ZipFile(zip_path, 'r') as zf:
        # Typical structure: Payload/<AppName>.app/Info.plist
        for zi in zf.infolist():
            parts = Path(zi.filename).parts
            if len(parts) >= 3 and parts[0] == "Payload" and parts[-1] == "Info.plist":
                # Ensure there is an .app directory in the path
                if any(p.endswith(".app") for p in parts):
                    # Determine app dir name for nicer output naming
                    app_dir = next((p for p in parts if p.endswith(".app")), None)
                    results.append((app_dir, zi.filename))
    return results

def read_zip_member_bytes(zip_path: str, member: str) -> bytes:
    with zipfile.ZipFile(zip_path, 'r') as zf:
        with zf.open(member, 'r') as f:
            return f.read()

def default_output_path_for_ipa(ipa_path: str, app_dir: str) -> Path:
    base = Path(ipa_path).with_suffix('')
    app_name = app_dir[:-4] if app_dir and app_dir.endswith('.app') else "App"
    return base.parent / f"{base.name}_{app_name}_Info.plist.xml"

def default_output_path_for_plist(plist_path: str) -> Path:
    p = Path(plist_path)
    return p.with_suffix(p.suffix + ".xml") if p.suffix != ".xml" else p

def ensure_parent_dir(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)

def convert_plist_file(plist_path: str, output: str | None):
    plist_path = Path(plist_path)
    try:
        with open(plist_path, "rb") as f:
            xml_bytes = convert_plist_bytes_to_xml(f.read())
    except Exception as e:
        print(f"[!] Failed to parse plist '{plist_path}': {e}", file=sys.stderr)
        sys.exit(2)

    out_path = Path(output) if output else default_output_path_for_plist(str(plist_path))
    ensure_parent_dir(out_path)
    with open(out_path, "wb") as f:
        f.write(xml_bytes)
    print(f"[+] Wrote XML plist: {out_path}")

def convert_ipa_info_plist(ipa_path: str, output: str | None, index: int | None):
    ipa_path = Path(ipa_path)
    infos = find_info_plists_in_ipa(str(ipa_path))
    if not infos:
        print(f"[!] No Info.plist found under Payload/*.app in '{ipa_path}'.", file=sys.stderr)
        sys.exit(3)

    # If multiple .app bundles exist, allow picking by index or convert all
    if index is not None:
        if index < 0 or index >= len(infos):
            print(f"[!] Index {index} out of range (found {len(infos)} app(s)).", file=sys.stderr)
            sys.exit(4)
        infos = [infos[index]]

    wrote_any = False
    for app_dir, plist_zip_path in infos:
        try:
            raw = read_zip_member_bytes(str(ipa_path), plist_zip_path)
            xml_bytes = convert_plist_bytes_to_xml(raw)
        except Exception as e:
            print(f"[!] Failed to parse '{plist_zip_path}' in '{ipa_path}': {e}", file=sys.stderr)
            continue

        if output:
            out_path = Path(output)
            # If converting multiple, avoid clobbering—append app name
            if len(infos) > 1 and out_path.is_dir():
                out_path = out_path / f"{ipa_path.stem}_{app_dir[:-4]}_Info.plist.xml"
        else:
            out_path = default_output_path_for_ipa(str(ipa_path), app_dir)

        ensure_parent_dir(out_path)
        with open(out_path, "wb") as f:
            f.write(xml_bytes)
        print(f"[+] {app_dir}: wrote XML plist -> {out_path}")
        wrote_any = True

    if not wrote_any:
        sys.exit(5)

def main():
    ap = argparse.ArgumentParser(description="Convert iOS plist to XML (works with .ipa or .plist).")
    ap.add_argument("input", help="Path to .ipa or .plist")
    ap.add_argument("-o", "--output",
                    help="Output file path (or directory if converting multiple). "
                         "If omitted, a sensible default is chosen.")
    ap.add_argument("--index", type=int,
                    help="If the IPA contains multiple .app bundles, convert only the one at this index (0-based).")
    args = ap.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[!] Input does not exist: {in_path}", file=sys.stderr)
        sys.exit(1)

    if in_path.suffix.lower() == ".ipa":
        # If user passed a directory in --output, keep it as a directory
        if args.output and Path(args.output).exists() and Path(args.output).is_dir():
            convert_ipa_info_plist(str(in_path), args.output, args.index)
        else:
            convert_ipa_info_plist(str(in_path), args.output, args.index)
    elif in_path.suffix.lower() == ".plist":
        convert_plist_file(str(in_path), args.output)
    else:
        # Try to detect by content if not a known suffix
        try:
            # If it's a zip, treat as IPA
            with zipfile.ZipFile(str(in_path), 'r'):
                pass
            convert_ipa_info_plist(str(in_path), args.output, args.index)
        except zipfile.BadZipFile:
            # Otherwise treat as plist
            convert_plist_file(str(in_path), args.output)

if __name__ == "__main__":
    main()
