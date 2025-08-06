---

# 🛡️ **GuardianAI**  
**AI-Powered Home Network Defense Assistant**

GuardianAI is a desktop application that monitors and protects your home network. It scans connected devices, analyzes logs with AI, and detects physical intrusions using your webcam. Built with **Tkinter**, it blends cybersecurity, AI, and computer vision into a user-friendly interface.

---

## 🚀 Features

| Category                  | Description                                                                 |
|---------------------------|-----------------------------------------------------------------------------|
| 🔍 **Network Scanner**     | Detects devices on your subnet with IP, MAC, hostname, and open ports       |
| 📚 **Log Management**      | Saves and exports scan logs to a local SQLite database                      |
| 🧠 **AI Classification**   | Uses Hugging Face Transformers to classify log severity and suggest actions |
| ⚙️ **Rule-Based Evaluation**| Highlights suspicious activity based on customizable rules                  |
| 🎥 **Intrusion Detection** | Uses webcam + OpenCV Haar cascades to detect human presence                 |
| 📤 **Export Options**      | Export logs to CSV or JSON                                                  |
| 🖥️ **Intuitive GUI**       | Tkinter-based interface with start/stop controls                           |

---

## 🛠️ Installation

### ✅ Prerequisites

- Python 3.10+
- Webcam (for intrusion detection)
- Compatible with Windows, Linux, macOS

### 📦 Setup Instructions

#### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/GuardianAI.git
cd GuardianAI
```

#### 2. Create & Activate Virtual Environment (Recommended)

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

#### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

#### 4. Connect Webcam

Ensure your webcam is connected and functioning for intrusion detection.

---

## ▶️ Usage

Run the GUI application:

```bash
python -m ui.gui
```

### 🖱️ GUI Controls

- **Scan Network:** Discover connected devices
- **Save Logs:** Store scan results in the database
- **Show Recent Logs:** View previous scans
- **AI Classify Logs:** Analyze severity and get recommendations
- **Start Intrusion Detection:** Activate webcam-based monitoring
- **Stop Intrusion Detection:** Disable webcam feed

---

## 📁 Project Structure

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

## 📦 Dependencies

| Package           | Purpose                          |
|-------------------|----------------------------------|
| `scapy`           | Network scanning                 |
| `opencv-python`   | Webcam & computer vision         |
| `tkinter`         | GUI framework (built-in)         |
| `transformers`    | AI classification (Hugging Face) |
| `sqlite3`         | Local database (built-in)        |
| `pyyaml`          | Config management                |

---

## 📝 Notes

- Run with sufficient permissions for network scanning.
- Intrusion detection requires a working webcam.
- AI model is lightweight and intended for demonstration.
- Logs and whitelist config are stored locally.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 📬 Contact

For questions or feedback, reach out to **Ahmad Abughanam**.

---

_Built with ❤️ by Ahmad — combining AI, cybersecurity, and lifestyle tech._

---
