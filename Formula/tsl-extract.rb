class TslExtract < Formula
  desc "Extract certificates from a Trust Service List (TSL) XML file"
  homepage "https://github.com/yourname/tsl-extract"
  url "https://github.com/yourname/tsl-extract/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "REPLACE_WITH_ACTUAL_SHA256_AFTER_TAGGING"
  license "MIT"

  # tsl-extract uses only the Python standard library, so no extra
  # PyPI dependencies are needed. We just need a recent Python 3.
  depends_on "python@3.12"

  def install
    # Copy the single-file tool into the Homebrew libexec area and
    # create a wrapper in bin/ so `tsl-extract` is on the user's PATH.
    libexec.install "tsl_extract.py"

    (bin/"tsl-extract").write <<~SHELL
      #!/bin/bash
      exec "#{Formula["python@3.12"].opt_bin}/python3" "#{libexec}/tsl_extract.py" "$@"
    SHELL
  end

  test do
    # Write a minimal valid TSL XML and check that the tool runs without error
    # and exits 0 when no certificates are present (just a warning).
    (testpath/"empty.xml").write <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
        <SchemeInformation/>
        <TrustServiceProviderList/>
      </TrustServiceStatusList>
    XML

    output = shell_output("#{bin}/tsl-extract empty.xml 2>&1")
    assert_match "no certificates found", output
  end
end
