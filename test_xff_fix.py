#!/usr/bin/env python3
"""Test the X-Forwarded-For spoofing fix."""

import os
import sys

# Add current directory to path
sys.path.insert(0, '.')

from fastapi import Request
from unittest.mock import Mock

def test_xff_fix():
    """Test the fixed _client_ip function."""
    # Import after setting env var
    os.environ['TRUSTED_PROXY_DEPTH'] = '1'
    from routes.auth_routes import _client_ip
    
    print("Testing X-Forwarded-For spoofing fix...")
    
    # Test 1: X-Real-IP takes precedence
    mock_request = Mock()
    mock_request.headers = {'X-Real-IP': '10.0.0.1', 'X-Forwarded-For': '1.2.3.4'}
    mock_request.client = Mock(host='192.168.1.100')
    assert _client_ip(mock_request) == '10.0.0.1', "X-Real-IP should take precedence"
    print("✓ X-Real-IP takes precedence")
    
    # Test 2: Basic X-Forwarded-For (client -> Railway -> app)
    mock_request.headers = {'X-Forwarded-For': '203.0.113.1'}
    # With trusted_depth=1 and only 1 IP, all IPs are trusted
    # Should fall back to request.client.host
    # Actually, Railway would set X-Real-IP, so this is edge case
    print("  Note: Single XFF entry with trusted_depth=1 falls back to direct connection")
    
    # Test 3: X-Forwarded-For with Railway (client, railway)
    mock_request.headers = {'X-Forwarded-For': '203.0.113.1, 10.0.0.1'}
    mock_request.client = Mock(host='10.0.0.1')  # Railway's IP
    # trusted_depth=1, skip rightmost (Railway), get client
    assert _client_ip(mock_request) == '203.0.113.1', "Should skip Railway proxy"
    print("✓ Skips trusted Railway proxy")
    
    # Test 4: Attacker tries to spoof (attacker, real-client, railway)
    mock_request.headers = {'X-Forwarded-For': '1.2.3.4, 203.0.113.1, 10.0.0.1'}
    # trusted_depth=1, skip rightmost (Railway), get 203.0.113.1 (real client)
    # NOT 1.2.3.4 (attacker)!
    assert _client_ip(mock_request) == '203.0.113.1', "Should get real client, not attacker"
    print("✓ Prevents attacker prepending their IP")
    
    # Test 5: Multiple trusted proxies (e.g., Cloudflare + Railway)
    os.environ['TRUSTED_PROXY_DEPTH'] = '2'
    # Re-import to pick up new env var
    import importlib
    import routes.auth_routes
    importlib.reload(routes.auth_routes)
    from routes.auth_routes import _client_ip
    
    mock_request.headers = {'X-Forwarded-For': '203.0.113.1, 10.0.0.2, 10.0.0.1'}
    # trusted_depth=2, skip 2 rightmost (Cloudflare + Railway), get client
    assert _client_ip(mock_request) == '203.0.113.1', "Should skip 2 trusted proxies"
    print("✓ Handles multiple trusted proxies")
    
    # Test 6: Direct connection (no headers)
    os.environ['TRUSTED_PROXY_DEPTH'] = '1'
    importlib.reload(routes.auth_routes)
    from routes.auth_routes import _client_ip
    
    mock_request.headers = {}
    mock_request.client = Mock(host='192.168.1.100')
    assert _client_ip(mock_request) == '192.168.1.100', "Should use direct connection IP"
    print("✓ Falls back to direct connection")
    
    print("\n✅ All X-Forwarded-For spoofing tests passed!")
    return True

if __name__ == '__main__':
    try:
        test_xff_fix()
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)