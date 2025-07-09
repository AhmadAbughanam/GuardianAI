# utils/rules.py

import yaml

SUSPICIOUS_PORTS = {23, 445, 3389, 135, 21, 1900}  # Telnet, SMB, RDP, etc.
MAX_OPEN_PORTS = 10


def load_whitelist():
    try:
        with open("config.yaml", "r") as f:
            config = yaml.safe_load(f)
            return config.get("whitelist", {"mac": [], "ip": []})
    except:
        return {"mac": [], "ip": []}


def evaluate_device(device):
    issues = []

    ip = device.get("ip")
    mac = device.get("mac", "").lower()
    hostname = device.get("hostname", "")
    open_ports = set(device.get("open_ports", []))

    whitelist = load_whitelist()

    # Rule 1: Unknown device
    if mac not in whitelist["mac"] and ip not in whitelist["ip"]:
        issues.append(
            {
                "ip": ip,
                "issue": "Unknown device detected",
                "severity": "Medium",
                "action": "Warn",
            }
        )

    # Rule 2: Suspicious ports open
    flagged_ports = open_ports & SUSPICIOUS_PORTS
    if flagged_ports:
        issues.append(
            {
                "ip": ip,
                "issue": f"Suspicious ports open: {sorted(flagged_ports)}",
                "severity": "High",
                "action": "Warn",
            }
        )

    # Rule 3: Too many open ports
    if len(open_ports) > MAX_OPEN_PORTS:
        issues.append(
            {
                "ip": ip,
                "issue": f"Excessive open ports: {len(open_ports)}",
                "severity": "Medium",
                "action": "Warn",
            }
        )

    return issues


def evaluate_all(devices):
    """
    Run rules on a list of scanned devices.
    """
    all_issues = []
    for dev in devices:
        issues = evaluate_device(dev)
        all_issues.extend(issues)
    return all_issues
