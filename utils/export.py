# utils/export.py

import csv
import json


def export_to_csv(devices, filepath):
    """
    Export a list of device dicts to CSV.
    Each device should contain keys: ip, mac, hostname, open_ports.
    """
    try:
        with open(filepath, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["IP Address", "MAC Address", "Hostname", "Open Ports"])
            for dev in devices:
                writer.writerow(
                    [
                        dev.get("ip", ""),
                        dev.get("mac", ""),
                        dev.get("hostname", ""),
                        ", ".join(str(p) for p in dev.get("open_ports", [])),
                    ]
                )
        return True
    except Exception as e:
        raise Exception(f"CSV Export Failed: {str(e)}")


def export_to_json(devices, filepath):
    """
    Export a list of device dicts to JSON.
    """
    try:
        with open(filepath, mode="w", encoding="utf-8") as f:
            json.dump(devices, f, indent=4)
        return True
    except Exception as e:
        raise Exception(f"JSON Export Failed: {str(e)}")
