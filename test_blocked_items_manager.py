#!/usr/bin/env python3
"""
Test script for the BlockedItemsManager
"""

import requests
import socket
import time
import sys

def test_blocked_items_manager():
    """Test the BlockedItemsManager functionality"""

    # Test adding blocked domains
    print("Testing BlockedItemsManager...")

    # Connect to the proxy
    socks5_proxy = "socks5://127.0.0.1:1080"

    # Test URLs that should trigger GFW blocking
    test_urls = [
        "https://www.google.com",
        "https://www.youtube.com",
        "https://www.facebook.com",
        "https://www.twitter.com",
        "https://www.instagram.com",
        "https://www.telegram.org",
    ]

    print(f"Testing {len(test_urls)} URLs to trigger blocking...")

    success_count = 0
    fail_count = 0

    for url in test_urls:
        domain = url.split("//")[1].split("/")[0]
        print(f"\nTesting {domain}...")

        try:
            # Try to connect through SOCKS5 proxy
            response = requests.get(
                url,
                proxies={"http": socks5_proxy, "https": socks5_proxy},
                timeout=5
            )

            # If successful, try direct connection to trigger potential blocking
            print(f"  Proxy connection successful (status: {response.status_code})")

            # Now try direct connection which might trigger GFW
            try:
                direct_response = requests.get(url, timeout=3)
                print(f"  Direct connection also successful")
            except requests.exceptions.ConnectionError as e:
                if "Connection reset by peer" in str(e):
                    print(f"  ⚠️ Direct connection reset - this should add to blocked items")
                else:
                    print(f"  Direct connection failed: {e}")
            except Exception as e:
                print(f"  Direct connection error: {e}")

            success_count += 1

        except requests.exceptions.ProxyConnectionError as e:
            print(f"  Proxy connection failed: {e}")
            fail_count += 1
        except requests.exceptions.Timeout:
            print(f"  Connection timeout")
            fail_count += 1
        except Exception as e:
            print(f"  Unexpected error: {e}")
            fail_count += 1

    print(f"\n=== Test Results ===")
    print(f"Successful connections: {success_count}")
    print(f"Failed connections: {fail_count}")

    # Check Web API for blocked items statistics
    try:
        response = requests.get("http://127.0.0.1:8080/api/blacklist")
        if response.status_code == 200:
            data = response.json()
            print(f"\n=== Blocked Items Statistics ===")
            print(f"Total blocked domains: {data.get('total_blocked_domains', 'N/A')}")
            print(f"Total blocked IPs: {data.get('total_blocked_ips', 'N/A')}")

            # Get top blocked domains
            top_response = requests.get("http://127.0.0.1:8080/api/blacklist/top")
            if top_response.status_code == 200:
                top_data = top_response.json()
                print("\nTop blocked domains:")
                for domain, info in top_data.get('top_blocked_domains', {}).items():
                    attempts = info.get('attempts', 0)
                    ports = info.get('ports', [])
                    reasons = info.get('failure_reasons', {})
                    print(f"  {domain}: {attempts} attempts")
                    if ports:
                        print(f"    Ports: {', '.join(map(str, ports))}")
                    if reasons:
                        print(f"    Reasons: {reasons}")
        else:
            print(f"Failed to get statistics: {response.status_code}")

    except Exception as e:
        print(f"Error checking statistics: {e}")

def test_port_scanning():
    """Test different ports on a blocked domain"""
    print("\n=== Testing Port Scanning ===")

    # Choose a domain likely to be blocked
    domain = "www.google.com"
    ports = [80, 443, 8080, 8443]

    print(f"Testing different ports on {domain}...")

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((domain, port))
            sock.close()

            if result == 0:
                print(f"  Port {port}: Open")
            elif result == 104:  # ECONNRESET
                print(f"  Port {port}: Connection reset (GFW detected)")
            else:
                print(f"  Port {port}: Error {result}")

        except Exception as e:
            print(f"  Port {port}: Exception - {e}")

if __name__ == "__main__":
    print("Blocked Items Manager Test")
    print("=" * 50)

    # Test basic functionality
    test_blocked_items_manager()

    # Test port scanning
    test_port_scanning()

    print("\nTest completed!")