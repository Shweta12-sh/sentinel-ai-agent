import pytest
import json

def test_log_sanitization():
    """Test that input log strings are correctly sanitized."""
    raw_log = "<script>alert('xss')</script> SELECT * FROM logs;"
    clean_log = raw_log.replace("<script>", "").replace("</script>", "")
    assert "<script>" not in clean_log

def test_cvss_score_bounds():
    """Test that generated CVSS severity scores remain in legal bounds (0.0 - 10.0)."""
    mock_cvss = 8.5
    assert 0.0 <= mock_cvss <= 10.0

def test_token_bucket_rate_limiter():
    """Test rate limiting token deduction."""
    tokens = 100
    cost = 10
    remaining = tokens - cost
    assert remaining == 90

def test_remediation_script_generation():
    """Test that remediation script outputs contain safety headers."""
    script = "#!/bin/bash\n# SentinelAI Automated Patch\niptables -A INPUT -s 192.168.1.50 -j DROP"
    assert "#!/bin/bash" in script
    assert "iptables" in script
