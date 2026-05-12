# tsl-extract

A tiny CLI tool that turns a **Trust Service List (TSL)** XML file into a set of
X.509 certificates. TSLs are published by national supervisory bodies (e.g.
the EU, UK, or US) and list the trust anchors for qualified electronic
signatures.

## Installation (via Homebrew)

```bash
brew tap yourname/tsl-extract
brew install tsl-extract
```

Or install directly from the formula file during development:

```bash
brew install --formula ./tsl-extract.rb
```

## Usage

```
tsl-extract [-h] [-f {pem,der,bundle}] [-o OUTPUT] [-v] tsl_file
```

### Arguments

| Flag | Description |
|------|-------------|
| `tsl_file` | Path to the TSL XML file |
| `-f pem` | Write one `.pem` file per certificate *(default)* |
| `-f der` | Write one `.der` file per certificate |
| `-f bundle` | Write all certificates into a single PEM bundle |
| `-o PATH` | Output directory (pem/der) or file (bundle). Defaults to `./certs/` or `./bundle.pem` |
| `-v` | Verbose: print each certificate label as it is written |

### Examples

```bash
# Extract individual PEM files into ./certs/
tsl-extract eu-lotl.xml

# Extract individual DER files into ./my-certs/
tsl-extract eu-lotl.xml -f der -o my-certs/

# Create a single PEM bundle
tsl-extract eu-lotl.xml -f bundle -o eu-trust-anchors.pem

# Verbose output
tsl-extract eu-lotl.xml -f bundle -v
```

## Where to get TSL files

| Source | URL |
|--------|-----|
| EU List of Trusted Lists (LOTL) | https://ec.europa.eu/tools/lotl/eu-lotl.xml |
| UK TSL | https://www.tscheme.org/UK_TSL |

## Development

The tool is a single Python file (`tsl_extract.py`) with **no third-party
dependencies** — it only uses the standard library (`xml.etree`, `base64`,
`argparse`, `pathlib`).

```bash
python3 tsl_extract.py --help
```

## License

MIT
