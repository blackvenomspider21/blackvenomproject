#!/usr/bin/env python3
"""
Web Security Header Auditor
Author: blackvenomspider21
Description: Audits a target web application's HTTP response headers for missing 
             security controls and outputs a basic risk assessment.
"""

import argparse
import sys
import requests
from urllib.parse import urlparse

# Critical security headers to audit with industry-standard remediation guidance
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections and guards against SSL Strip/MitM attacks.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
    },
    "Content-Security-Policy": {
        "description": "Restricts sources of content (scripts, styles) to mitigate XSS and data injection.",
        "remediation": "Define a robust Content-Security-Policy header restricting untrusted script sources."
    },
    "X-Frame-Options": {
        "description": "Prevents page framing to defend against Clickjacking attacks.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'."
    },
    "X-Content-Type-Options": {
        "description": "Stops MIME-type sniffing to prevent browsers from executing non-executable files.",
        "remediation": "Add 'X-Content-Type-Options: nosniff'."
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is included with requests.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
    },
    "Permissions-Policy": {
        "description": "Restricts browser features like camera, microphone, and geolocation APIs.",
        "remediation": "Configure Permissions-Policy to explicitly disable unnecessary browser features."
    }
}

def audit_headers(target_url):
    # Ensure protocol prefix exists
    if not urlparse(target_url).scheme:
        target_url = "https://" + target_url

    print(f"\n[+] Auditing Target: {target_url}\n" + "=" * 60)

    try:
        response = requests.get(target_url, timeout=10, allow_redirects=True)
        headers = response.headers
    except requests.exceptions.RequestException as e:
        print(f"[-] Error connecting to target: {e}")
        sys.exit(1)

    missing_count = 0
    total_headers = len(SECURITY_HEADERS)

    for header, info in SECURITY_HEADERS.items():
        if header in headers:
            print(f"[PASS] {header}")
            print(f"       Value: {headers[header]}\n")
        else:
            print(f"[FAIL] {header} is MISSING!")
            print(f"       Impact: {info['description']}")
            print(f"       Fix:    {info['remediation']}\n")
            missing_count += 1

    # Score calculation
    pass_count = total_headers - missing_count
    score_percentage = (pass_count / total_headers) * 100

    print("=" * 60)
    print(f"[*] Audit Complete: {pass_count}/{total_headers} security headers present.")
    print(f"[*] Security Score: {score_percentage:.1f}%")

    if score_percentage == 100:
        print("[*] Risk Level: LOW - Excellent security header posture.")
    elif score_percentage >= 50:
        print("[*] Risk Level: MEDIUM - Basic headers configured, but critical defenses are missing.")
    else:
        print("[*] Risk Level: HIGH - Missing essential defenses against XSS, Clickjacking, and MitM.")

def main():
    parser = argparse.ArgumentParser(description="Audit web application security response headers.")
    parser.add_argument("-u", "--url", required=True, help="Target URL or domain (e.g., example.com)")
    args = parser.parse_args()

    audit_headers(args.url)

if __name__ == "__main__":
    main()