# Log Analyzer
A Python tool that parses SSH authentication logs and
detects suspicious IP addresses with repeated failed logins.

## How to run
python log_analyzer.py

## What it does
- Counts failed login attempts per IP address
- Lists the most targeted usernames
- Flags IPs with 3 or more failed attempts
