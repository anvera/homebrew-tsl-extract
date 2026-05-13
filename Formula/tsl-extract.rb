class TslExtract < Formula
  desc "Extract certificates from a Trust-service Status List (TSL) XML file"
  homepage "https://github.com/anvera/homebrew-tsl-extract"
  url "https://github.com/anvera/homebrew-tsl-extract/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "1fc81ceb247841d7e8c10cf9ddc65c7899739e83d31ce434ce360e269d807b64"
  license "MIT"

  depends_on "python@3.12"

  def install
    system Formula["python@3.12"].opt_bin/"python3", "-m", "pip", "install",
           "--prefix=#{prefix}", "--no-deps", "--no-build-isolation", "."
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
