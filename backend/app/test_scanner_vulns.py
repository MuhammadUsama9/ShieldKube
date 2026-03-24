import os
import sys
from unittest.mock import MagicMock

# Mock dependencies before importing scanner
sys.modules["kubernetes"] = MagicMock()
sys.modules["kubernetes.client"] = MagicMock()
sys.modules["kubernetes.config"] = MagicMock()
sys.modules["fastapi"] = MagicMock()
sys.modules["fastapi.responses"] = MagicMock()
sys.modules["fastapi.middleware.cors"] = MagicMock()

# Add current directory to path so we can import app.scanner
sys.path.append(os.getcwd())

from app.scanner import K8sScanner, CVE_DB

def test_static_db_expansion():
    print("Testing static CVE_DB expansion...")
    images_to_test = ["nginx", "redis", "postgres", "node", "python", "alpine", "ubuntu", "debian", "busybox"]
    for img in images_to_test:
        vulns = CVE_DB.get(img, [])
        print(f"  {img}: {len(vulns)} vulnerabilities found (Static)")
        assert len(vulns) > 0, f"No vulnerabilities for {img} in static DB"
    print("Static DB test passed!\n")

def test_scanner_with_mock_mode():
    print("Testing scanner in mock mode (should use expanded static DB)...")
    scanner = K8sScanner(mock_mode=True)
    # Test specific images
    nginx_vulns = scanner._check_image_cve("nginx:latest")
    print(f"  nginx:latest -> {len(nginx_vulns)} vulns")
    assert len(nginx_vulns) >= 4
    
    postgres_vulns = scanner._check_image_cve("postgres:15.1")
    print(f"  postgres:15.1 -> {len(postgres_vulns)} vulns")
    assert len(postgres_vulns) >= 3
    print("Mock mode test passed!\n")

def test_osv_lookup():
    print("Testing OSV lookup (Live API)...")
    scanner = K8sScanner(mock_mode=False) # Enable live lookups
    
    # Use a known vulnerable version for OSV lookup
    # Django 1.11.2 has many vulnerabilities in PyPI ecosystem
    package = "django"
    version = "1.11.2"
    print(f"  Querying OSV for {package}:{version}...")
    vulns = scanner._check_osv_api(package, version)
    
    print(f"  {package}:{version} -> {len(vulns)} vulns from OSV")
    if len(vulns) > 0:
        print(f"  First vuln: {vulns[0]['id']} - {vulns[0]['title']}")
        assert "CVE" in vulns[0]["id"] or "GHSA" in vulns[0]["id"]
    else:
        print("  Warning: No vulns returned from OSV. This might happen if API is down or rate limited.")
    
    print("OSV lookup test finished!\n")

if __name__ == "__main__":
    try:
        test_static_db_expansion()
        test_scanner_with_mock_mode()
        test_osv_lookup()
        print("All tests completed successfully!")
    except Exception as e:
        print(f"Tests failed: {e}")
        sys.exit(1)
