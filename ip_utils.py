import ipaddress
import re


def extract_ip(line):
    """
    Extract and validate an IPv4 address from a log line.
    """

    match = re.search(
        r'ip=(\d{1,3}(?:\.\d{1,3}){3})',
        line
    )

    if not match:
        return None

    ip = match.group(1)

    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return None


def is_private_ip(ip):
    """
    Check whether an IP belongs to a private network.
    """

    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_valid_ip(ip):
    """
    Validate an IP address.
    """

    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
