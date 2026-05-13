class TslExtract < Formula
  desc "Extract certificates from a Trust-service Status List (TSL) XML file"
  homepage "https://github.com/anvera/homebrew-tsl-extract"
  url "https://github.com/anvera/homebrew-tsl-extract/archive/refs/tags/v0.6.0.tar.gz"
  sha256 "b59fca8ca64b898b8b008b7c706ec51a743b37538a4d3898f43efa09d25a953b"
  license "MIT"

  depends_on "python@3.12"

  def install
    libexec.install "src/tsl_extract.py"
    (bin/"tsl-extract").write <<~BASH
      #!/bin/bash
      exec "#{Formula["python@3.12"].opt_bin}/python3.12" "#{libexec}/tsl_extract.py" "$@"
    BASH
  end

  test do
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
