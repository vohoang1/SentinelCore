from wp_engine.wp.wp_parser import parse_line
from wp_engine.wp.recon_detector import is_recon, is_malicious_ua, is_wp_login_attempt
from wp_engine.wp.xmlrpc_detector import is_xmlrpc_abuse
from wp_engine.wp import lifecycle_detector
from wp_engine.intelligence.scoring_engine import ScoringEngine


def test_parser():
    line = '192.168.1.5 - - [03/Mar/2026:08:45:22 +0700] "POST /wp-login.php HTTP/1.1" 200 532 "-" "Mozilla/5.0"'
    event = parse_line(line)
    assert event is not None, "Parser should parse valid log line"
    assert event["ip"] == "192.168.1.5"
    assert event["method"] == "POST"
    assert event["path"] == "/wp-login.php"
    assert event["status"] == "200"
    print("✅ test_parser PASSED")


def test_recon():
    event = {"path": "/wp-content/plugins/vuln-plugin/", "ua": "Mozilla/5.0"}
    assert is_recon(event), "Should detect plugin path probe"

    event2 = {"path": "/backup.zip", "ua": "Mozilla/5.0"}
    assert is_recon(event2), "Should detect .zip extension"

    event3 = {"path": "/index.php", "ua": "Mozilla/5.0"}
    assert not is_recon(event3), "Normal path should not trigger recon"
    print("✅ test_recon PASSED")


def test_xmlrpc():
    event = {"path": "/xmlrpc.php", "method": "POST"}
    assert is_xmlrpc_abuse(event), "Should detect XMLRPC POST"

    event2 = {"path": "/xmlrpc.php", "method": "GET"}
    assert not is_xmlrpc_abuse(event2), "GET to xmlrpc should not trigger"
    print("✅ test_xmlrpc PASSED")


def test_malicious_ua():
    event = {"ua": "sqlmap/1.7 (https://sqlmap.org)", "path": "/"}
    assert is_malicious_ua(event), "Should detect sqlmap UA"

    event2 = {"ua": "Mozilla/5.0 (Windows NT 10.0)", "path": "/"}
    assert not is_malicious_ua(event2), "Normal UA should not trigger"
    print("✅ test_malicious_ua PASSED")


def test_lifecycle():
    ip = "10.99.0.1"
    lifecycle_detector.mark_recon(ip)

    upload_event = {"ip": ip, "path": "/wp-content/uploads/", "method": "POST"}
    lifecycle_detector.track_event(upload_event)

    verify_event = {"ip": ip, "path": "/wp-content/uploads/shell.php", "method": "GET"}
    lifecycle_detector.track_event(verify_event)

    assert lifecycle_detector.is_full_lifecycle(ip), "Should detect full kill-chain"
    print("✅ test_lifecycle PASSED")


def test_scoring():
    engine = ScoringEngine()

    score = engine.update_score("1.2.3.4", {"recon": True})
    assert score == 10.0, f"Expected 10, got {score}"

    score = engine.update_score("1.2.3.4", {"xmlrpc_abuse": True})
    assert score == 25.0, f"Expected 25, got {score}"

    score = engine.update_score("1.2.3.4", {"wp_login_fail": True, "brute_force": True})
    assert score == 50.0, f"Expected 50, got {score}"

    assert engine.should_block("1.2.3.4"), "Score >= 50 should trigger block"
    print("✅ test_scoring PASSED")


if __name__ == "__main__":
    test_parser()
    test_recon()
    test_xmlrpc()
    test_malicious_ua()
    test_lifecycle()
    test_scoring()
    print("\n🎯 All tests passed!")
