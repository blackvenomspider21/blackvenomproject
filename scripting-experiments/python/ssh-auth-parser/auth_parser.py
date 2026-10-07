#!/usr/bin/env python3
"""
SSH Auth Log Anomaly Parser
Author: blackvenomspider21
Description: Parses Linux authentication logs (/var/log/auth.log or journalctl stream) 
             to detect brute-force attacks, invalid user enumeration, and IP anomalies.
"""

import argparse
import re
import sys
from collections import defaultdict

# Regex patterns for SSH authentication events
FAILED_PASS_REGEX = re.compile(
    r'Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+'
)
ACCEPTED_PASS_REGEX = re.compile(
    r'Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+'
)
INVALID_USER_REGEX = re.compile(
    r'Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)

def parse_log_stream(file_object, threshold):
    failed_attempts_by_ip = defaultdict(int)
    invalid_user_attempts = defaultdict(set)
    successful_logins = defaultdict(list)
    total_lines = 0

    for line in file_object:
        total_lines += 1

        # Check for failed password attempts
        failed_match = FAILED_PASS_REGEX.search(line)
        if failed_match:
            ip = failed_match.group('ip')
            user = failed_match.group('user')
            failed_attempts_by_ip[ip] += 1
            invalid_user_attempts[ip].add(user)
            continue

        # Check for invalid user probes
        invalid_match = INVALID_USER_REGEX.search(line)
        if invalid_match:
            ip = invalid_match.group('ip')
            user = invalid_match.group('user')
            invalid_user_attempts[ip].add(user)
            continue

        # Check for successful logins
        accepted_match = ACCEPTED_PASS_REGEX.search(line)
        if accepted_match:
            ip = accepted_match.group('ip')
            user = accepted_match.group('user')
            successful_logins[ip].append(user)

    # Output Summary Report
    print("\n" + "=" * 70)
    print("          SSH AUTHENTICATION ANOMALY DETECTION REPORT          ")
    print("=" * 70)
    print(f"[*] Processed {total_lines} log lines.\n")

    # Flag potential brute-force IPs
    print(f"[!] SUSPECTED BRUTE-FORCE ATTACKS (>{threshold} Failed Attempts):")
    print("-" * 70)
    brute_force_found = False
    for ip, count in sorted(failed_attempts_by_ip.items(), key=lambda x: x[1], reverse=True):
        if count >= threshold:
            brute_force_found = True
            users_targeted = len(invalid_user_attempts[ip])
            print(f"  [ALERT] Source IP: {ip:<15} | Failed Attempts: {count:<5} | Targeted Users: {users_targeted}")

    if not brute_force_found:
        print("  [INFO] No IPs exceeded the brute-force threshold.")

    # Flag Successful Logins
    print("\n[*] SUCCESSFUL AUTHENTICATION EVENTS:")
    print("-" * 70)
    if successful_logins:
        for ip, users in successful_logins.items():
            print(f"  [PASS] Source IP: {ip:<15} | Logged in as: {', '.join(set(users))}")
            if ip in failed_attempts_by_ip and failed_attempts_by_ip[ip] >= threshold:
                print(f"         └── [CRITICAL] IP {ip} HAD SUCCEEDED AFTER SUSPICIOUS FAILED ATTEMPTS!")
    else:
        print("  [INFO] No successful SSH logins recorded in log input.")

    print("=" * 70 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Parse Linux SSH auth logs for anomalies.")
    parser.add_argument("-f", "--file", help="Path to auth log file (e.g., /var/log/auth.log or /var/log/secure)")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="Failed login threshold to flag brute force (default: 5)")

    args = parser.parse_args()

    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
                parse_log_stream(f, args.threshold)
        except FileNotFoundError:
            print(f"[-] Error: File '{args.file}' not found.")
            sys.exit(1)
        except PermissionError:
            print(f"[-] Permission denied reading '{args.file}'. Try running with sudo.")
            sys.exit(1)
    else:
        # If no file specified, attempt to read from standard input (e.g., piped from journalctl)
        if not sys.stdin.isatty():
            parse_log_stream(sys.stdin, args.threshold)
        else:
            print("[-] Error: Specify an auth log file (-f) or pipe input via journalctl.")
            print("    Example 1: python3 auth_parser.py -f /var/log/auth.log")
            print("    Example 2: journalctl -u ssh | python3 auth_parser.py")
            sys.exit(1)

if __name__ == "__main__":
    main()