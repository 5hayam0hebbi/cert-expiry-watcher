from certwatch import Result, classify, issuer_name, parse_endpoint, to_markdown


def test_parse_plain_host():
    assert parse_endpoint("GitHub.com\n") == ("github.com", 443)


def test_parse_port_url_and_comment():
    assert parse_endpoint("https://example.com:8443/path  # admin") == ("example.com", 8443)


def test_parse_skips_blank_and_comment_lines():
    assert parse_endpoint("   ") is None
    assert parse_endpoint("# just a note") is None


def test_classify_thresholds():
    assert classify(90, warn=30, crit=7) == "OK"
    assert classify(30, warn=30, crit=7) == "WARN"
    assert classify(7, warn=30, crit=7) == "CRIT"
    assert classify(-2, warn=30, crit=7) == "CRIT"


def test_issuer_prefers_organization():
    cert = {"issuer": ((("countryName", "US"),), (("organizationName", "Let's Encrypt"),), (("commonName", "R11"),))}
    assert issuer_name(cert) == "Let's Encrypt"


def test_markdown_puts_problems_first():
    ok = Result("a.com", "OK", 80, "2027-01-01", "X", "80 days left")
    bad = Result("b.com", "ERROR", None, "", "", "verification failed")
    table = to_markdown([ok, bad])
    assert table.index("b.com") < table.index("a.com")
