class TslExtract < Formula
  desc "Extract certificates from a Trust-service Status List (TSL) XML file"
  homepage "https://github.com/anvera/homebrew-tsl-extract"
  url "https://github.com/anvera/homebrew-tsl-extract/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "46971aa13ae9d95d67472c0051cf1fae47cfb8e6002ff5b0ed35e8d5894c3579"
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
