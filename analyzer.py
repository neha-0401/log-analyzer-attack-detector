import re
from collections import defaultdict
from datetime import datetime

from ip_utils import extract_ip
from incident_report import (
    create_incident,
    save_incident
)
from email_alert import send_alert


LOG_FILE = "security.log"

# Number of failures required before detection
BRUTE_FORCE_THRESHOLD = 5

# Email address that receives alerts
ALERT_RECIPIENT = "nehhak04@gmail.com"


def extract_username(line):
    """
    Extract username from a log line.
    """

    match = re.search(
        r'user=([A-Za-z0-9_.-]+)',
        line
    )

    if match:
        return match.group(1)

    return "unknown"


def extract_timestamp(line):
    """
    Extract timestamp from the beginning of the log line.
    """

    match = re.match(
        r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',
        line
    )

    if match:

        try:
            return datetime.strptime(
                match.group(1),
                "%Y-%m-%d %H:%M:%S"
            )

        except ValueError:
            return None

    return None


def analyze_log():

    failed_by_ip = defaultdict(int)
    failed_by_user = defaultdict(int)

    successful_logins = 0
    failed_logins = 0

    events = []

    with open(LOG_FILE, "r") as file:

        for line in file:

            ip = extract_ip(line)

            if not ip:
                continue

            username = extract_username(line)
            timestamp = extract_timestamp(line)

            if "Login failed" in line:

                failed_logins += 1

                failed_by_ip[ip] += 1
                failed_by_user[username] += 1

                events.append({
                    "timestamp": timestamp,
                    "ip": ip,
                    "username": username,
                    "type": "FAILED"
                })

            elif "Login successful" in line:

                successful_logins += 1

                events.append({
                    "timestamp": timestamp,
                    "ip": ip,
                    "username": username,
                    "type": "SUCCESS"
                })

    return (
        successful_logins,
        failed_logins,
        failed_by_ip,
        failed_by_user,
        events
    )


def detect_attacks(
    failed_by_ip,
    failed_by_user,
    events
):

    incidents = []

    # --------------------------------
    # Brute-force detection
    # --------------------------------

    for ip, count in failed_by_ip.items():

        if count >= BRUTE_FORCE_THRESHOLD:

            username = "unknown"

            # Find the username associated
            # with this IP
            for event in events:

                if (
                    event["ip"] == ip
                    and event["type"] == "FAILED"
                ):

                    username = event["username"]
                    break

            incident = create_incident(
                source_ip=ip,
                username=username,
                failed_attempts=count,
                attack_type="BRUTE_FORCE"
            )

            incidents.append(incident)

    # --------------------------------
    # Password spraying detection
    # --------------------------------

    user_ips = defaultdict(set)

    for event in events:

        if event["type"] == "FAILED":

            user_ips[event["username"]].add(
                event["ip"]
            )

    for username, ips in user_ips.items():

        if len(ips) >= 3:

            incident = create_incident(
                source_ip=", ".join(ips),
                username=username,
                failed_attempts=len(ips),
                attack_type="PASSWORD_SPRAYING"
            )

            incidents.append(incident)

    return incidents


def display_report(
    success,
    failed,
    failed_by_ip,
    failed_by_user,
    incidents
):

    print("\n")
    print("=" * 55)
    print("              SECURITY LOG REPORT")
    print("=" * 55)

    print()
    print(f"Successful logins : {success}")
    print(f"Failed logins     : {failed}")

    print()
    print("FAILED ATTEMPTS BY IP")
    print("-" * 55)

    if not failed_by_ip:

        print("No failed login attempts found.")

    else:

        for ip, count in failed_by_ip.items():

            if count >= BRUTE_FORCE_THRESHOLD:

                print(
                    f"{ip:<20} "
                    f"{count:<5} "
                    f"🚨 SUSPICIOUS"
                )

            else:

                print(
                    f"{ip:<20} "
                    f"{count:<5}"
                )

    print()
    print("FAILED ATTEMPTS BY USER")
    print("-" * 55)

    for username, count in failed_by_user.items():

        print(
            f"{username:<20} "
            f"{count} attempts"
        )

    print()
    print("SECURITY INCIDENTS")
    print("-" * 55)

    if not incidents:

        print("No suspicious incidents detected.")

    else:

        for incident in incidents:

            print(
                f"🚨 {incident['severity']:<8} "
                f"{incident['type']:<20} "
                f"IP: {incident['source_ip']}"
            )


def process_log():

    try:

        (
            success,
            failed,
            failed_by_ip,
            failed_by_user,
            events
        ) = analyze_log()

    except FileNotFoundError:

        print("❌ security.log not found.")

        return

    incidents = detect_attacks(
        failed_by_ip,
        failed_by_user,
        events
    )

    display_report(
        success,
        failed,
        failed_by_ip,
        failed_by_user,
        incidents
    )

    # Save incidents
    for incident in incidents:

        save_incident(incident)

        # Send email only for important incidents
        if incident["severity"] in [
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        ]:

            send_alert(
                source_ip=incident["source_ip"],
                username=incident["username"],
                attempts=incident["failed_attempts"],
                severity=incident["severity"],
                attack_type=incident["type"],
                recipient=ALERT_RECIPIENT
            )


def main():

    while True:

        print()
        print("=" * 40)
        print("          LOG ANALYZER")
        print("=" * 40)

        print("1. Analyze security log")
        print("2. Exit")

        choice = input("\nChoose an option: ")

        if choice == "1":

            process_log()

        elif choice == "2":

            print("\nGoodbye!")
            break

        else:

            print("❌ Invalid option.")


if __name__ == "__main__":
    main()
