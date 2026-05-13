"""
Tests for tsl_extract.py
Run with:  python -m pytest tests/ -v
"""

import base64
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree as ET

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
import tsl_extract as t


# A real (tiny, self-signed) DER certificate encoded as base64.
_CERT_B64 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a2rwplBQLzHPZe5TNJK"
    "BghfBDyUhFyaRIHxRInNlMRnHgOBhBPMOeIbLrWwSEQTbGP/FBxFPLzRJZFluRXg"
    "cwWkFKqxqSMc6pBzJAsDUGMsKcGBQa6BQFXG6cIkLAnuTr8GGQRcSQAEAQID"
)


def _make_tsl(providers: list[dict]) -> str:
    tsp_blocks = []
    for p in providers:
        svc_blocks = []
        for s in p["services"]:
            cert_els = "\n".join(
                f"<ds:X509Certificate>{c}</ds:X509Certificate>"
                for c in s.get("certs", [])
            )
            svc_blocks.append(f"""
        <TSPService>
          <ServiceInformation>
            <ServiceName><Name xml:lang="en">{s["name"]}</Name></ServiceName>
            <ServiceDigitalIdentity>
              <DigitalId>{cert_els}</DigitalId>
            </ServiceDigitalIdentity>
          </ServiceInformation>
        </TSPService>""")
        tsp_blocks.append(f"""
    <TrustServiceProvider>
      <TSPName><Name xml:lang="en">{p["tsp"]}</Name></TSPName>
      <TSPServices>{"".join(svc_blocks)}
      </TSPServices>
    </TrustServiceProvider>""")

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<TrustServiceStatusList\n'
        '  xmlns="http://uri.etsi.org/02231/v2#"\n'
        '  xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n'
        '  <TrustServiceProviderList>\n'
        + "".join(tsp_blocks) +
        '\n  </TrustServiceProviderList>\n'
        '</TrustServiceStatusList>\n'
    )


def _parse(xml: str) -> ET.ElementTree:
    return ET.parse(StringIO(xml))


# ---------------------------------------------------------------------------
# find_certificates
# ---------------------------------------------------------------------------

class TestFindCertificates:
    def test_empty_tsl_returns_empty_list(self):
        certs = t.find_certificates(_parse(_make_tsl([])))
        assert certs == []

    def test_single_cert_found(self):
        xml = _make_tsl([{
            "tsp": "My CA",
            "services": [{"name": "Root", "certs": [_CERT_B64]}],
        }])
        certs = t.find_certificates(_parse(xml))
        assert len(certs) == 1
        label, b64 = certs[0]
        assert label == "My CA - Root"
        assert b64 == _CERT_B64

    def test_multiple_providers_and_certs(self):
        xml = _make_tsl([
            {"tsp": "CA Alpha", "services": [
                {"name": "Svc1", "certs": [_CERT_B64]},
                {"name": "Svc2", "certs": [_CERT_B64, _CERT_B64]},
            ]},
            {"tsp": "CA Beta", "services": [
                {"name": "Svc3", "certs": [_CERT_B64]},
            ]},
        ])
        assert len(t.find_certificates(_parse(xml))) == 4

    def test_label_uses_tsp_and_service_name(self):
        xml = _make_tsl([{
            "tsp": "Acme Trust",
            "services": [{"name": "QC Root", "certs": [_CERT_B64]}],
        }])
        label, _ = t.find_certificates(_parse(xml))[0]
        assert label == "Acme Trust - QC Root"

    def test_service_with_no_certs_is_skipped(self):
        xml = _make_tsl([{
            "tsp": "Empty CA",
            "services": [{"name": "No certs", "certs": []}],
        }])
        assert t.find_certificates(_parse(xml)) == []


# ---------------------------------------------------------------------------
# _pick_name
# ---------------------------------------------------------------------------

class TestPickName:
    def _el(self, xml: str) -> ET.Element:
        return ET.fromstring(xml)

    def test_prefers_english(self):
        xml = """<TSPName xmlns="http://uri.etsi.org/02231/v2#">
          <Name xml:lang="de">Deutsch</Name>
          <Name xml:lang="en">English</Name>
        </TSPName>"""
        parent = ET.Element("{http://uri.etsi.org/02231/v2#}Root")
        parent.append(self._el(xml))
        assert t._pick_name(parent, "tsl:TSPName") == "English"

    def test_falls_back_to_first_name(self):
        xml = """<TSPName xmlns="http://uri.etsi.org/02231/v2#">
          <Name xml:lang="fr">Français</Name>
        </TSPName>"""
        parent = ET.Element("{http://uri.etsi.org/02231/v2#}Root")
        parent.append(self._el(xml))
        assert t._pick_name(parent, "tsl:TSPName") == "Français"


# ---------------------------------------------------------------------------
# safe_filename
# ---------------------------------------------------------------------------

class TestSafeFilename:
    def test_basic(self):
        assert t.safe_filename("My CA - Root", 1, "pem") == "0001_My_CA_-_Root.pem"

    def test_special_chars_replaced(self):
        fname = t.safe_filename("CA/Root:2024", 2, "der")
        assert "/" not in fname
        assert ":" not in fname

    def test_long_name_truncated(self):
        fname = t.safe_filename("A" * 100, 1, "pem")
        assert len(fname) <= 5 + 60 + 4

    def test_empty_name_fallback(self):
        assert t.safe_filename("", 3, "pem") == "0003_cert.pem"


# ---------------------------------------------------------------------------
# der_to_pem
# ---------------------------------------------------------------------------

class TestDerToPem:
    def test_includes_markers(self):
        pem = t.der_to_pem(base64.b64decode(_CERT_B64))
        assert "-----BEGIN CERTIFICATE-----" in pem
        assert "-----END CERTIFICATE-----" in pem

    def test_includes_label_comment(self):
        pem = t.der_to_pem(base64.b64decode(_CERT_B64), label="Test CA")
        assert pem.startswith("# Test CA\n")

    def test_no_label_no_comment(self):
        pem = t.der_to_pem(base64.b64decode(_CERT_B64))
        assert not pem.startswith("#")

    def test_roundtrip(self):
        der = base64.b64decode(_CERT_B64)
        pem = t.der_to_pem(der)
        lines = [l for l in pem.splitlines()
                 if l and not l.startswith("#") and not l.startswith("---")]
        assert base64.b64decode("".join(lines)) == der


# ---------------------------------------------------------------------------
# write_pem / write_der / write_bundle
# ---------------------------------------------------------------------------

class TestWriters:
    @pytest.fixture
    def one_cert(self):
        return [("Test CA - Root", _CERT_B64)]

    def test_write_pem_creates_file(self, tmp_path, one_cert):
        count = t.write_pem(one_cert, tmp_path)
        assert count == 1
        files = list(tmp_path.glob("*.pem"))
        assert len(files) == 1
        assert "-----BEGIN CERTIFICATE-----" in files[0].read_text()

    def test_write_der_creates_file(self, tmp_path, one_cert):
        count = t.write_der(one_cert, tmp_path)
        assert count == 1
        files = list(tmp_path.glob("*.der"))
        assert len(files) == 1
        assert len(files[0].read_bytes()) > 0

    def test_write_bundle_single_file(self, tmp_path, one_cert):
        out = tmp_path / "bundle.pem"
        assert t.write_bundle(one_cert, out) == 1
        assert "-----BEGIN CERTIFICATE-----" in out.read_text()

    def test_write_bundle_multiple_certs(self, tmp_path):
        certs = [("CA A - Svc1", _CERT_B64), ("CA B - Svc2", _CERT_B64)]
        out = tmp_path / "bundle.pem"
        t.write_bundle(certs, out)
        assert out.read_text().count("-----BEGIN CERTIFICATE-----") == 2

    def test_write_pem_multiple_certs(self, tmp_path):
        certs = [("CA A - Svc1", _CERT_B64), ("CA B - Svc2", _CERT_B64)]
        assert t.write_pem(certs, tmp_path) == 2
        assert len(list(tmp_path.glob("*.pem"))) == 2

    def test_write_creates_output_dir(self, tmp_path):
        t.write_pem([("CA", _CERT_B64)], tmp_path / "deep" / "nested")
        assert (tmp_path / "deep" / "nested").is_dir()


# ---------------------------------------------------------------------------
# print_list
# ---------------------------------------------------------------------------

class TestPrintList:
    def test_output_contains_label(self, capsys):
        t.print_list([("Acme Trust - Root CA", _CERT_B64)])
        assert "Acme Trust - Root CA" in capsys.readouterr().out

    def test_output_contains_total(self, capsys):
        t.print_list([("CA A", _CERT_B64), ("CA B", _CERT_B64)])
        assert "Total: 2" in capsys.readouterr().out

    def test_output_contains_byte_size(self, capsys):
        t.print_list([("CA", _CERT_B64)])
        assert "bytes" in capsys.readouterr().out

    def test_no_files_written(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        t.print_list([("CA", _CERT_B64)])
        assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# CLI integration (main)
# ---------------------------------------------------------------------------

class TestCLI:
    @pytest.fixture
    def tsl_file(self, tmp_path):
        xml = _make_tsl([{
            "tsp": "Test CA",
            "services": [{"name": "Root", "certs": [_CERT_B64]}],
        }])
        p = tmp_path / "test.xml"
        p.write_text(xml)
        return p

    def _run(self, args: list[str]):
        with patch("sys.argv", ["tsl-extract"] + args):
            t.main()

    def test_list_flag_prints_without_writing(self, tsl_file, tmp_path, capsys, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._run([str(tsl_file), "--list"])
        out = capsys.readouterr().out
        assert "Test CA - Root" in out
        assert "Total: 1" in out
        assert not (tmp_path / "certs").exists()

    def test_pem_format_default(self, tsl_file, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._run([str(tsl_file)])
        assert len(list((tmp_path / "certs").glob("*.pem"))) == 1

    def test_pem_explicit(self, tsl_file, tmp_path):
        out_dir = tmp_path / "out"
        self._run([str(tsl_file), "-f", "pem", "-o", str(out_dir)])
        assert len(list(out_dir.glob("*.pem"))) == 1

    def test_der_format(self, tsl_file, tmp_path):
        out_dir = tmp_path / "der_out"
        self._run([str(tsl_file), "-f", "der", "-o", str(out_dir)])
        assert len(list(out_dir.glob("*.der"))) == 1

    def test_bundle_format(self, tsl_file, tmp_path):
        out_file = tmp_path / "my.pem"
        self._run([str(tsl_file), "-f", "bundle", "-o", str(out_file)])
        assert "-----BEGIN CERTIFICATE-----" in out_file.read_text()

    def test_missing_file_exits_1(self, tmp_path):
        with pytest.raises(SystemExit) as exc:
            self._run([str(tmp_path / "nonexistent.xml")])
        assert exc.value.code == 1

    def test_invalid_xml_exits_1(self, tmp_path):
        bad = tmp_path / "bad.xml"
        bad.write_text("this is not xml <<<")
        with pytest.raises(SystemExit) as exc:
            self._run([str(bad)])
        assert exc.value.code == 1

    def test_verbose_prints_labels(self, tsl_file, tmp_path, capsys, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._run([str(tsl_file), "-v"])
        assert "Test CA - Root" in capsys.readouterr().out

    def test_list_and_format_are_mutually_exclusive(self, tsl_file):
        with pytest.raises(SystemExit) as exc:
            self._run([str(tsl_file), "--list", "-f", "pem"])
        assert exc.value.code == 2
