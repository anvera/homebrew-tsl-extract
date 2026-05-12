#!/usr/bin/env python3
"""
tsl-extract: Extract certificates from a Trust Service List (TSL) XML file.
"""

import argparse
import base64
import sys
import textwrap
from pathlib import Path
from xml.etree import ElementTree as ET

# TSL XML namespaces
# All known real-world TSLs (EU LOTL, member-state lists, gematik, etc.) use
# the v2# namespace introduced in ETSI TS 102 231 v3 and carried forward into
# ETSI TS 119 612.  No alternative namespace versions have been observed in
# production TSLs, so a single namespace map is sufficient.
NAMESPACES = {
    "tsl": "http://uri.etsi.org/02231/v2#",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xades": "http://uri.etsi.org/01903/v1.3.2#",
}


def find_certificates(tree: ET.ElementTree) -> list[tuple[str, str]]:
    """
    Walk the TSL XML tree and return all (label, base64_der) certificate pairs.
    The label is derived from the TSP name + service name for traceability.
    """
    root = tree.getroot()
    certs = []

    for tsp in root.findall(".//tsl:TrustServiceProvider", NAMESPACES):
        tsp_name = _pick_name(tsp, "tsl:TSPName")

        for svc in tsp.findall(".//tsl:TSPService", NAMESPACES):
            svc_name = _pick_name(svc, "tsl:ServiceName")
            label = f"{tsp_name} - {svc_name}" if svc_name else tsp_name

            for cert_el in svc.findall(".//ds:X509Certificate", NAMESPACES):
                raw = cert_el.text
                if raw:
                    b64 = "".join(raw.split())
                    certs.append((label, b64))

    return certs


def _pick_name(el: ET.Element, tag: str) -> str:
    """Return the first English name value, or first available, or empty string."""
    names = el.findall(f".//{tag}/tsl:Name", NAMESPACES)
    if not names:
        return ""
    for n in names:
        if n.get("{http://www.w3.org/XML/1998/namespace}lang", "").lower() in ("en", "eng"):
            return (n.text or "").strip()
    return (names[0].text or "").strip()


def b64_to_der(b64: str) -> bytes:
    return base64.b64decode(b64)


def der_to_pem(der: bytes, label: str = "") -> str:
    b64 = base64.b64encode(der).decode("ascii")
    lines = textwrap.wrap(b64, 64)
    comment = f"# {label}\n" if label else ""
    return comment + "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def safe_filename(name: str, index: int, ext: str) -> str:
    """Turn a TSP/service label into a safe filename."""
    safe = "".join(c if c.isalnum() or c in "-_ " else "_" for c in name)
    safe = safe.strip().replace(" ", "_")[:60]
    return f"{index:04d}_{safe}.{ext}" if safe else f"{index:04d}_cert.{ext}"


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_pem(certs: list[tuple[str, str]], output_dir: Path) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    for i, (label, b64) in enumerate(certs, 1):
        pem = der_to_pem(b64_to_der(b64), label)
        (output_dir / safe_filename(label, i, "pem")).write_text(pem)
    return len(certs)


def write_der(certs: list[tuple[str, str]], output_dir: Path) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    for i, (label, b64) in enumerate(certs, 1):
        (output_dir / safe_filename(label, i, "der")).write_bytes(b64_to_der(b64))
    return len(certs)


def write_bundle(certs: list[tuple[str, str]], output_file: Path) -> int:
    parts = [der_to_pem(b64_to_der(b64), label) for label, b64 in certs]
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text("".join(parts))
    return len(certs)


def print_list(certs: list[tuple[str, str]]) -> None:
    """Print a human-readable inventory of certificates without writing any files."""
    col_w = 6
    print(f"{'#':<{col_w}}  Label")
    print("-" * (col_w + 2) + "-" * 60)
    for i, (label, b64) in enumerate(certs, 1):
        der = b64_to_der(b64)
        print(f"{i:<{col_w}}  {label}  ({len(der):,} bytes)")
    print()
    print(f"Total: {len(certs)} certificate(s)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tsl-extract",
        description="Extract certificates from a Trust Service List (TSL) XML file.",
    )
    parser.add_argument("tsl_file", type=Path, help="Path to the TSL XML file")

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "-l", "--list",
        action="store_true",
        help="List certificates found in the TSL without writing any files.",
    )
    mode.add_argument(
        "-f", "--format",
        choices=["pem", "der", "bundle"],
        default="pem",
        help="Output format: pem (individual .pem files), der (individual .der files), "
             "bundle (single PEM bundle file). Default: pem",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Output directory (pem/der) or file path (bundle). "
             "Defaults to ./certs/ for pem/der, or ./bundle.pem for bundle. "
             "Ignored when --list is used.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print each certificate label as it is written (ignored with --list).",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    tsl_path: Path = args.tsl_file
    if not tsl_path.exists():
        print(f"Error: file not found: {tsl_path}", file=sys.stderr)
        sys.exit(1)

    try:
        tree = ET.parse(tsl_path)
    except ET.ParseError as exc:
        print(f"Error: failed to parse XML: {exc}", file=sys.stderr)
        sys.exit(1)

    certs = find_certificates(tree)
    if not certs:
        print("Warning: no certificates found in the TSL file.", file=sys.stderr)
        sys.exit(0)

    # --list: print an inventory and exit without touching the filesystem
    if args.list:
        print_list(certs)
        return

    fmt: str = args.format

    if args.verbose:
        for label, _ in certs:
            print(f"  {label}")

    if fmt == "pem":
        out = args.output or Path("certs")
        count = write_pem(certs, out)
        print(f"Wrote {count} PEM certificate(s) to {out}/")

    elif fmt == "der":
        out = args.output or Path("certs")
        count = write_der(certs, out)
        print(f"Wrote {count} DER certificate(s) to {out}/")

    elif fmt == "bundle":
        out = args.output or Path("bundle.pem")
        count = write_bundle(certs, out)
        print(f"Wrote {count} certificate(s) to bundle: {out}")


if __name__ == "__main__":
    main()
