"""Quick test for the _is_private_or_reserved function with IPv6 support."""
from detector import _is_private_or_reserved

tests = [
    ("127.0.0.1",       True),
    ("127.255.255.1",   True),
    ("192.168.1.99",    True),
    ("10.0.0.1",        True),
    ("172.16.0.1",      True),
    ("172.31.255.254",  True),
    ("169.254.1.1",     True),
    ("0.0.0.0",         True),
    ("224.0.0.1",       True),
    ("8.8.8.8",         False),
    ("142.250.70.78",   False),
    ("93.184.216.34",   False),
    # IPv6
    ("::1",             True),
    ("fc00::1",         True),
    ("fd12:3456::1",    True),
    ("fe80::1",         True),
    ("2607:f8b0::1",    False),
]

passed = 0
failed = 0
for ip, expected in tests:
    result = _is_private_or_reserved(ip)
    status = "PASS" if result == expected else "FAIL"
    if status == "PASS":
        passed += 1
    else:
        failed += 1
    print(f"  {status}: {ip:20s} -> {result} (expected {expected})")

print(f"\n{passed}/{passed+failed} passed, {failed} failed")
