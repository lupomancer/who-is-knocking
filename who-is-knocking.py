#!/usr/bin/env python3
"""
SSH Login Log Analyzer - Extract failed password attempts
"""

import re
from datetime import datetime
from collections import defaultdict

def parse_ssh_log(log_file):
    """
    Parse SSH log file and extract failed password attempts.
    Returns a list of failed login attempts.
    """
    failed_logins = []
    
    # Pattern to match failed password lines
    # Examples:
    # "Failed password for centos from 161.35.144.171 port 39778 ssh2"
    # "Failed password for invalid user svn from 92.118.39.92 port 37202 ssh2"
    pattern = r'Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)'
    
    try:
        with open(log_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                if 'Failed password' in line:
                    match = re.search(pattern, line)
                    if match:
                        # Extract timestamp, user, IP, and port
                        timestamp = ' '.join(line.split()[:3])  # "Feb  8 03:17:05"
                        user = match.group(1)
                        ip_address = match.group(2)
                        port = match.group(3)
                        
                        failed_logins.append({
                            'timestamp': timestamp,
                            'user': user,
                            'ip': ip_address,
                            'port': port,
                            'line': line.strip()
                        })
    except FileNotFoundError:
        print(f"Error: File '{log_file}' not found.")
        return []
    
    return failed_logins


def print_summary(failed_logins, output_file=None):
    """Print a summary of failed login attempts to console or file."""
    if not failed_logins:
        message = "No failed password attempts found in the log."
        if output_file:
            output_file.write(message + "\n")
        else:
            print(message)
        return
    
    lines = []
    lines.append(f"\n{'='*100}")
    lines.append(f"SSH FAILED PASSWORD ATTEMPTS - Total: {len(failed_logins)}")
    lines.append(f"{'='*100}\n")
    
    # Add all failed logins
    lines.append(f"{'Timestamp':<16} {'User':<20} {'IP Address':<18} {'Port':<6}")
    lines.append("-" * 60)
    for login in failed_logins:
        lines.append(f"{login['timestamp']:<16} {login['user']:<20} {login['ip']:<18} {login['port']:<6}")
    
    # Add statistics
    lines.append(f"\n{'='*100}")
    lines.append("STATISTICS")
    lines.append(f"{'='*100}\n")
    
    # Count by user
    users = defaultdict(int)
    for login in failed_logins:
        users[login['user']] += 1
    
    lines.append(f"Failed attempts by user:")
    for user, count in sorted(users.items(), key=lambda x: x[1], reverse=True):
        lines.append(f"  {user:<30} {count:>5} attempts")
    
    # Count by IP
    ips = defaultdict(int)
    for login in failed_logins:
        ips[login['ip']] += 1
    
    lines.append(f"\nFailed attempts by IP address:")
    for ip, count in sorted(ips.items(), key=lambda x: x[1], reverse=True):
        lines.append(f"  {ip:<30} {count:>5} attempts")
    
    # Write to file or print to console
    output_text = "\n".join(lines)
    if output_file:
        output_file.write(output_text + "\n")
    else:
        print(output_text)


def main():
    log_file = "secure"
    output_file = "failed_logins.txt"
    
    print(f"Analyzing SSH login log for failed password attempts...")
    print(f"Writing results to {output_file}...\n")
    
    failed_logins = parse_ssh_log(log_file)
    
    with open(output_file, 'w') as f:
        print_summary(failed_logins, f)
    
    print(f"✓ Analysis complete! Results saved to {output_file}")


if __name__ == "__main__":
    main()
