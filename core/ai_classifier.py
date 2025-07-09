# core/ai_classifier.py

from transformers import pipeline


class AIClassifier:
    def __init__(self):
        # Sentiment-analysis pipeline used as proxy for severity classification
        self.classifier = pipeline("sentiment-analysis")

    def classify(self, device_info: dict) -> dict:
        """
        Classify severity of a device scan/log entry.

        device_info example:
        {
            'ip': '192.168.1.10',
            'mac': 'AA:BB:CC:DD:EE:FF',
            'hostname': 'device-01',
            'open_ports': [22, 80, 443]
        }

        Returns:
        {
            'severity': 'Low'|'Medium'|'High',
            'recommendation': str
        }
        """

        text = self._generate_text(device_info)
        result = self.classifier(text)[0]

        label = result["label"]
        score = result["score"]

        # Map sentiment labels to severity
        if label == "NEGATIVE":
            severity = "High"
            recommendation = (
                "Potential threat detected. Investigate device and ports immediately."
            )
        elif label == "POSITIVE":
            if score > 0.9:
                severity = "Low"
                recommendation = "Device appears safe. Continue routine monitoring."
            else:
                severity = "Medium"
                recommendation = "Some suspicious activity. Review open ports and logs."
        else:
            severity = "Medium"
            recommendation = "Review device for unusual activity."

        return {"severity": severity, "recommendation": recommendation}

    def _generate_text(self, device_info):
        ports = ", ".join(str(p) for p in device_info.get("open_ports", []))
        hostname = device_info.get("hostname") or "unknown device"
        return (
            f"Device {hostname} with IP {device_info.get('ip')} has open ports: {ports}. "
            f"Analyze for potential security risks."
        )


# Quick test
if __name__ == "__main__":
    ai = AIClassifier()
    test_device = {
        "ip": "192.168.1.10",
        "mac": "AA:BB:CC:DD:EE:FF",
        "hostname": "office-printer",
        "open_ports": [80, 443],
    }
    result = ai.classify(test_device)
    print("Severity:", result["severity"])
    print("Recommendation:", result["recommendation"])
