class OsidbMcp < Formula
  desc "Model Context Protocol (MCP) server for OSIDB"
  homepage "https://github.com/vdanen/osidb-mcp"
  url "https://files.pythonhosted.org/packages/f2/bc/b78cb3ee5dee13df7829e5431ee7b93b58cba5f7c9e8479417b439daa80b/osidb_mcp-0.2.0.tar.gz"
  sha256 "829257b00139f4b0e40901234dcd13e2c6226624c1bc171d87d7cf9b912f883b"
  license "MIT"

  depends_on "python@3.13"

  skip_clean "libexec"

  def install
    python3 = Formula["python@3.13"].opt_bin/"python3.13"
    system python3, "-m", "venv", "--clear", libexec
    ENV.delete("PIP_NO_BINARY")
    ENV.delete("PIP_REQUIRE_HASHES")
    system libexec/"bin/pip", "install", "--upgrade", "pip"
    system libexec/"bin/pip", "install", "."
    bin.install_symlink libexec/"bin/osidb-mcp"
  end

  test do
    assert_match %r{\A\d+\.\d+\.\d+\n\z}, shell_output("#{bin}/osidb-mcp --version")
  end
end
