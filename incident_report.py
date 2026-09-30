import json
from datetime import datetime


INCIDENT_FILE = "incidents.json"


def calculate_severity(attempts):
    if attempts >= 20:
        return "CRITICAL"

    elif attempts >= 10:
        return "HIGH"

    elif attempts >= 5:
        return "MEDIUM"

    else:
        return "LOW"


def create_incident(
    source_ip,
    username,
    failed_attempts,
    attack_type
):

    severity = calculate_severity(failed_attempts)

    incident = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": source_ip,
        "username": username,
        "failed_attempts": failed_attempts,
        "severity": severity,
        "type": attack_type
    }

    return incident


def save_incident(incident):

    try:
        with open(INCIDENT_FILE, "r") as file:
            incidents = json.load(file)

    except (FileNotFoundError, json.JSONDecodeError):
        incidents = []

    incidents.append(incident)

    with open(INCIDENT_FILE, "w") as file:
        json.dump(
            incidents,
            file,
           indent=4
        )
