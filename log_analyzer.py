import os
import re
from collections import Counter

LOG_FILE = "auth.log"
THRESHOLD = 3  # عدد المحاولات الفاشلة قبل ما نعتبر الـ IP مشبوه

SAMPLE_LOG = """Oct 24 10:01:12 server sshd[1201]: Failed password for root from 203.0.113.5 port 22 ssh2
Oct 24 10:01:15 server sshd[1202]: Failed password for root from 203.0.113.5 port 22 ssh2
Oct 24 10:01:19 server sshd[1203]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2
Oct 24 10:01:25 server sshd[1204]: Failed password for invalid user test from 203.0.113.5 port 22 ssh2
Oct 24 10:05:02 server sshd[1210]: Accepted password for nurai from 192.168.1.20 port 22 ssh2
Oct 24 10:07:44 server sshd[1215]: Failed password for nurai from 198.51.100.7 port 22 ssh2
Oct 24 10:09:10 server sshd[1220]: Failed password for invalid user oracle from 198.51.100.9 port 22 ssh2
Oct 24 10:09:14 server sshd[1221]: Failed password for invalid user oracle from 198.51.100.9 port 22 ssh2
Oct 24 10:09:20 server sshd[1222]: Failed password for root from 198.51.100.9 port 22 ssh2
"""

PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})"
)


def create_sample_log(path):
    with open(path, "w") as f:
        f.write(SAMPLE_LOG)


def analyze(path):
    ips = Counter()
    users = Counter()
    with open(path, "r") as f:
        for line in f:
            match = PATTERN.search(line)
            if match:
                users[match.group(1)] += 1
                ips[match.group(2)] += 1
    return ips, users


def print_report(ips, users):
    total = sum(ips.values())
    print("=== Failed Login Report ===")
    print("Total failed attempts:", total)

    print("\nTop IP addresses:")
    for ip, count in ips.most_common(5):
        flag = "  <-- SUSPICIOUS" if count >= THRESHOLD else ""
        print(f"  {ip}: {count}{flag}")

    print("\nMost targeted usernames:")
    for user, count in users.most_common(5):
        print(f"  {user}: {count}")


def main():
    if not os.path.exists(LOG_FILE):
        print("No log file found. Creating a sample log...")
        create_sample_log(LOG_FILE)
    ips, users = analyze(LOG_FILE)
    if not ips:
        print("No failed login attempts found.")
        return
    print_report(ips, users)


if __name__ == "__main__":
    main()