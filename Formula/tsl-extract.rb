class TslExtract < Formula
  desc "Extract certificates from a Trust-service Status List (TSL) XML file"
  homepage "https://github.com/anvera/homebrew-tsl-extract"
  url "https://github.com/anvera/homebrew-tsl-extract/archive/refs/tags/v0.4.0.tar.gz"
  sha256 "aeaa0b0251af9119d016d5f08cac01c142315168dd595f3860b26025f07132d8"
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
