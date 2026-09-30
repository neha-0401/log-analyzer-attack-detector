import os
import smtplib

from email.message import EmailMessage
from dotenv import load_dotenv


load_dotenv()


def send_alert(
    source_ip,
    username,
    attempts,
    severity,
    attack_type,
    recipient
):
    """
    Send a security alert email.
    """

    sender = os.getenv("ALERT_EMAIL")
    password = os.getenv("ALERT_EMAIL_PASSWORD")

    if not sender or not password:
        print("❌ Email credentials are not configured.")
        return False

    message = EmailMessage()

    message["Subject"] = (
        f"[{severity}] Security Alert - {attack_type}"
    )

    message["From"] = sender
    message["To"] = recipient

    message.set_content(
        f"""
SECURITY ALERT
==============

Attack Type: {attack_type}
Severity: {severity}

Source IP:
{source_ip}

Username:
{username}

Failed Attempts:
{attempts}

The Log Analyzer detected suspicious authentication activity.

Please investigate the source IP and affected account.
"""
    )

    try:

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465
        ) as server:

            server.login(
                sender,
                password
            )

            server.send_message(message)

        print("📧 Email alert sent successfully.")

        return True

    except Exception as error:

        print(f"❌ Email failed: {error}")

        return False
