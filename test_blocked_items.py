#!/usr/bin/env python3
"""
Simple test to verify BlockedItemsManager functionality
"""

import requests
import socket
import time

def test_direct_connection():
    """Test direct connection to a blocked domain"""
    print("Testing direct connection to google.com...")

    try:
        # This should trigger the GFW reset if in China
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(("www.google.com", 80))
        sock.close()

        if result == 0:
            print("  Connection successful")
        elif result == 104:  # ECONNRESET
            print("  Connection reset (GFW detected)")
        else:
            print(f"  Connection failed with error code: {result}")

    except Exception as e:
        print(f"  Exception: {e}")

def test_socks5_connection():
    """Test SOCKS5 proxy connection"""
    print("\nTesting SOCKS5 proxy connection...")

    socks5_proxy = "socks5://127.0.0.1:1080"

    try:
        response = requests.get(
            "http://www.google.com",
            proxies={"http": socks5_proxy},
            timeout=10
        )
        print(f"  Proxy connection successful: {response.status_code}")
    except Exception as e:
        print(f"  Proxy connection failed: {e}")

def check_blocked_items_api():
    """Check the blocked items via Web API"""
    print("\nChecking blocked items via API...")

    try:
        response = requests.get("http://127.0.0.1:8080/api/blacklist")
        if response.status_code == 200:
            data = response.json()
            print(f"  Total blocked: {data}")
        else:
            print(f"  API error: {response.status_code}")
    except Exception as e:
        print(f"  Failed to check API: {e}")

if __name__ == "__main__":
    print("BlockedItemsManager Test")
    print("=" * 40)

    # First try direct connection
    test_direct_connection()

    # Then try through proxy
    test_socks5_connection()

    # Check API
    check_blocked_items_api()

    print("\nTest completed!")