import argparse
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

from tsl_extract import (
    find_certificates,
    print_list,
    write_bundle,
    write_der,
    write_pem,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tsl-extract",
        description="Extract certificates from a Trust-service Status List (TSL) XML file.",
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
