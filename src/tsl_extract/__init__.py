"""
tsl-extract: Extract certificates from a Trust-service Status List (TSL) XML file.
"""

import base64
import textwrap
from pathlib import Path
from xml.etree import ElementTree as ET

NAMESPACES = {
    "tsl": "http://uri.etsi.org/02231/v2#",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xades": "http://uri.etsi.org/01903/v1.3.2#",
}


def find_certificates(tree: ET.ElementTree) -> list[tuple[str, str]]:
    """Walk the TSL XML tree and return all (label, base64_der) certificate pairs."""
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
    col_w = 6
    print(f"{'#':<{col_w}}  Label")
    print("-" * (col_w + 2) + "-" * 60)
    for i, (label, b64) in enumerate(certs, 1):
        der = b64_to_der(b64)
        print(f"{i:<{col_w}}  {label}  ({len(der):,} bytes)")
    print()
    print(f"Total: {len(certs)} certificate(s)")
