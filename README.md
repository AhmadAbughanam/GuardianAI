````markdown
# 🛡️ GuardianAI — AI-Powered Home Network Defense Assistant

## Overview

GuardianAI is a desktop application that helps monitor and protect your home network by scanning connected devices and open ports, analyzing logs with AI-powered classification, and detecting physical intrusions using your webcam. It combines cybersecurity fundamentals with AI and computer vision in a user-friendly GUI built with Tkinter.

---

## Features

- **Network Scanner:** Detects devices on your local subnet with IP, MAC, hostname, and open ports.
- **Log Management:** Save, view, and export scan logs in SQLite database.
- **AI Classification:** Uses a lightweight AI model (via HuggingFace Transformers) to classify scan log severity and recommend actions.
- **Rule-Based Evaluation:** Highlights suspicious devices or port activity based on customizable rules.
- **Physical Intrusion Detection:** Uses your laptop webcam and OpenCV Haar cascades to detect human presence and alert you.
- **Export:** Export logs to CSV or JSON for offline analysis.
- **Intuitive GUI:** Built with Tkinter, includes start/stop controls for scanning and intrusion detection.

---

## Installation

### Prerequisites

- Python 3.10+
- Webcam (for intrusion detection)
- Windows/Linux/macOS

### Setup

1. Clone the repo:

   ```bash
   git clone https://github.com/yourusername/GuardianAI.git
   cd GuardianAI
   ```
````

2. Create and activate a virtual environment (optional but recommended):

   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Ensure your webcam is connected for intrusion detection.

---

## Usage

Run the GUI app:

```bash
python -m ui.gui
```

### GUI Controls

- **Scan Network:** Scan your local network for connected devices.
- **Save Logs:** Save the current scan data to the local database.
- **Show Recent Logs:** Display recent scan logs.
- **AI Classify Logs:** Analyze logs for severity and get recommendations.
- **Start Intrusion Detection:** Enable webcam-based physical intrusion detection.
- **Stop Intrusion Detection:** Disable the webcam feed and detection.

---

## Project Structure

```
GuardianAI/
├── core/
│   ├── scanner.py         # Network scanning logic
│   ├── log_parser.py      # Log saving and formatting
│   ├── ai_classifier.py   # AI-based log classification
│   └── intrusion_cv.py    # Webcam-based intrusion detection
├── data/
│   ├── logs.db            # SQLite database for logs
│   └── mock_syslogs.txt   # Sample logs for testing
├── ui/
│   └── gui.py             # Tkinter GUI application
├── utils/
│   ├── rules.py           # Rule-based device evaluation
│   ├── notifier.py        # Alert utilities
│   └── export.py          # Export logs functionality
├── config.yaml            # Config and whitelist data
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

---

## Dependencies

- `scapy` – Network scanning
- `opencv-python` – Webcam and computer vision
- `tkinter` – GUI framework (comes with Python)
- `transformers` – AI classification (HuggingFace)
- `sqlite3` – Database (built-in)
- `pyyaml` – Config management

---

## Notes

- Run the app with sufficient permissions to perform network scans.
- Intrusion detection requires a working webcam.
- AI model used is lightweight and intended for demonstration.
- Logs and whitelist config stored locally.

---

## License

[MIT License](LICENSE)

---

## Contact

For questions or feedback, reach out to Ahmad Abughanam.

---

_Built with ❤️ by Ahmad — combining AI, cybersecurity, and lifestyle tech._

```

```
