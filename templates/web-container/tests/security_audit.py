"""Test négatif : le flag ne fuit pas par les chemins non prévus."""

import os
import sys
import urllib.error
import urllib.request

URL = os.environ.get("TARGET_URL", "http://127.0.0.1:22000")
FLAG = os.environ.get("FLAG", "CCTF{local_test_only}")

leaks = []
for path in ("/healthz", "/robots.txt", "/.git/HEAD", "/does-not-exist"):
    try:
        with urllib.request.urlopen(URL + path, timeout=10) as r:
            if FLAG in r.read().decode(errors="replace") or FLAG in str(r.headers):
                leaks.append(path)
    except urllib.error.HTTPError as e:
        if FLAG in e.read().decode(errors="replace"):
            leaks.append(path)
if leaks:
    print(f"FUITE du flag sur : {leaks}")
    sys.exit(1)
print("AUDIT OK")
