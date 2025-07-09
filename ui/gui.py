import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from core.scanner import DeviceScanner
from core.log_parser import save_scan_results, fetch_recent_logs, format_for_display
from core.ai_classifier import AIClassifier  # ✅ NEW
from utils.rules import evaluate_all
from utils.export import export_to_csv, export_to_json
from tkinter import filedialog  # already built-in, may already exist
import yaml
from threading import Thread
import datetime
from core.intrusion_cv import IntrusionDetector
from tkinter import messagebox


def load_config():
    try:
        with open("config.yaml", "r") as f:
            return yaml.safe_load(f)
    except:
        return {}


def save_config(data):
    with open("config.yaml", "w") as f:
        yaml.dump(data, f)


class GuardianAIGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("GuardianAI – Home Network Defense Assistant")
        self.root.geometry("850x600")
        self.root.resizable(False, False)

        self.devices = []
        self.detector = IntrusionDetector(alert_callback=self.intrusion_alert)

        self.tree_items = []  # Keep references to Treeview rows

        self.setup_widgets()

    def setup_widgets(self):
        # Frame for Buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        tk.Button(
            button_frame, text="🔍 Scan Network", command=self.run_scan, width=20
        ).grid(row=0, column=0, padx=5)
        tk.Button(
            button_frame, text="💾 Save Logs", command=self.save_logs, width=20
        ).grid(row=0, column=1, padx=5)
        tk.Button(
            button_frame,
            text="📜 Show Recent Logs",
            command=self.show_recent_logs,
            width=20,
        ).grid(row=0, column=2, padx=5)
        tk.Button(
            button_frame, text="🧠 Classify Logs", command=self.classify_logs, width=20
        ).grid(
            row=0, column=3, padx=5
        )  # ✅ NEW
        tk.Button(
            button_frame,
            text="🛡️ Run Security Check",
            command=self.run_security_check,
            width=20,
        ).grid(row=1, column=0, padx=5, pady=5)
        tk.Button(
            button_frame, text="📤 Export CSV", command=self.export_csv, width=20
        ).grid(row=1, column=1, padx=5, pady=5)
        tk.Button(
            button_frame, text="📤 Export JSON", command=self.export_json, width=20
        ).grid(row=1, column=2, padx=5, pady=5)

        tk.Button(
            button_frame, text="⚙ Settings", command=self.open_settings, width=20
        ).grid(row=1, column=3, padx=5, pady=5)

        tk.Button(
            button_frame,
            text="▶️ Start Intrusion Detection",
            command=self.start_intrusion,
        ).grid(row=1, column=0, padx=5, pady=5)
        tk.Button(
            button_frame, text="⏹ Stop Intrusion Detection", command=self.stop_intrusion
        ).grid(row=1, column=1, padx=5, pady=5)

        # Treeview for Devices
        self.tree = ttk.Treeview(
            self.root, columns=("IP", "MAC", "Hostname", "Open Ports"), show="headings"
        )
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("MAC", text="MAC Address")
        self.tree.heading("Hostname", text="Hostname")
        self.tree.heading("Open Ports", text="Open Ports")
        self.tree.column("IP", width=150)
        self.tree.column("MAC", width=180)
        self.tree.column("Hostname", width=180)
        self.tree.column("Open Ports", width=280)
        self.tree.pack(pady=10, padx=10, fill="x")
        self.tree.bind("<Button-3>", self.right_click)

        # Scrolled Text for Status / Logs
        self.status_box = scrolledtext.ScrolledText(self.root, height=12)
        self.status_box.pack(padx=10, pady=10, fill="both")

    def right_click(self, event):
        selected = self.tree.identify_row(event.y)
        if not selected:
            return

        def mark_as_safe():
            item = self.tree.item(selected)["values"]
            ip, mac = item[0], item[1]
            config = load_config()
            whitelist = config.get("whitelist", {"mac": [], "ip": []})
            if mac and mac not in whitelist["mac"]:
                whitelist["mac"].append(mac)
            if ip and ip not in whitelist["ip"]:
                whitelist["ip"].append(ip)
            config["whitelist"] = whitelist
            save_config(config)
            self.log(f"Marked {ip} / {mac} as safe.")

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="✅ Mark as Safe", command=mark_as_safe)
        menu.post(event.x_root, event.y_root)

    def log(self, message):
        self.status_box.insert(tk.END, message + "\n")
        self.status_box.see(tk.END)

    def run_scan(self):
        self.tree.delete(*self.tree.get_children())
        self.devices = []
        self.tree_items = []
        self.log("Starting network scan...")
        try:
            scanner = DeviceScanner()
            self.devices = scanner.full_scan()
            if not self.devices:
                self.log("No devices found.")
                messagebox.showinfo(
                    "Scan Complete", "No devices detected on the network."
                )
                return

            for dev in self.devices:
                row = self.tree.insert(
                    "",
                    "end",
                    values=(
                        dev["ip"],
                        dev["mac"],
                        dev["hostname"] or "Unknown",
                        ", ".join(str(p) for p in dev["open_ports"]),
                    ),
                )
                self.tree_items.append((row, dev))
            self.log(f"Scan complete. {len(self.devices)} device(s) found.")
        except Exception as e:
            self.log(f"Error during scan: {str(e)}")
            messagebox.showerror("Scan Error", str(e))

    def save_logs(self):
        if not self.devices:
            self.log("No scan results to save.")
            messagebox.showwarning("Nothing to Save", "Run a scan before saving logs.")
            return
        try:
            save_scan_results(self.devices)
            self.log("Scan results saved to database.")
            messagebox.showinfo("Saved", "Scan logs saved successfully.")
        except Exception as e:
            self.log(f"Error saving logs: {str(e)}")
            messagebox.showerror("Save Error", str(e))

    def show_recent_logs(self):
        try:
            logs = fetch_recent_logs(limit=5)
            if not logs:
                self.log("No logs found in database.")
                messagebox.showinfo("Logs", "No previous logs found.")
                return
            self.log("Recent Logs:")
            self.log("-" * 70)
            for log in logs:
                self.log(format_for_display(log))
                self.log("-" * 70)
        except Exception as e:
            self.log(f"Error fetching logs: {str(e)}")
            messagebox.showerror("Load Error", str(e))

    def classify_logs(self):
        if not self.devices:
            self.log("No devices to classify. Run a scan first.")
            messagebox.showwarning(
                "No Devices", "Please run a scan before classifying logs."
            )
            return
        try:
            self.log("Classifying devices using AI...")
            classifier = AIClassifier()
            for idx, (row_id, dev) in enumerate(self.tree_items):
                result = classifier.classify(dev)
                severity = result["severity"]
                recommendation = result["recommendation"]
                self.log(f"[{dev['ip']}] Severity: {severity} — {recommendation}")

                # Optionally color the row based on severity
                if severity == "High":
                    self.tree.item(row_id, tags=("high",))
                elif severity == "Medium":
                    self.tree.item(row_id, tags=("medium",))
                else:
                    self.tree.item(row_id, tags=("low",))

            # Define row colors
            self.tree.tag_configure("high", background="#ffcccc")
            self.tree.tag_configure("medium", background="#fff2cc")
            self.tree.tag_configure("low", background="#ccffcc")

            self.log("Classification complete.")
        except Exception as e:
            self.log(f"AI classification error: {str(e)}")
            messagebox.showerror("AI Error", str(e))

    def run_security_check(self):
        if not self.devices:
            self.log("No devices to analyze. Run a scan first.")
            messagebox.showwarning("No Devices", "Run a scan before checking security.")
            return

        try:
            self.log("Running rule-based security analysis...")
            issues = evaluate_all(self.devices)
            if not issues:
                self.log("✅ No issues detected. All devices look safe.")
                return

            for issue in issues:
                ip = issue["ip"]
                msg = f"[{ip}] {issue['issue']} — Severity: {issue['severity']}"
                self.log(msg)

                # Tag TreeView rows with colors based on severity
                for row_id, dev in self.tree_items:
                    if dev["ip"] == ip:
                        if issue["severity"] == "High":
                            self.tree.item(row_id, tags=("sec_high",))
                        elif issue["severity"] == "Medium":
                            self.tree.item(row_id, tags=("sec_medium",))
                        else:
                            self.tree.item(row_id, tags=("sec_low",))

            # Apply color styles
            self.tree.tag_configure("sec_high", background="#ffcccc")
            self.tree.tag_configure("sec_medium", background="#fff0b3")
            self.tree.tag_configure("sec_low", background="#ccffcc")

            self.log(f"🛡️ Security analysis complete. {len(issues)} issue(s) detected.")
        except Exception as e:
            self.log(f"Security check error: {str(e)}")
            messagebox.showerror("Security Error", str(e))

    def export_csv(self):
        if not self.devices:
            self.log("No scan data to export. Run a scan first.")
            messagebox.showwarning("Export Failed", "No device data to export.")
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV Files", "*.csv")]
        )
        if not filepath:
            return
        try:
            export_to_csv(self.devices, filepath)
            self.log(f"Device data exported to CSV: {filepath}")
            messagebox.showinfo("Export Successful", "CSV file saved.")
        except Exception as e:
            self.log(str(e))
            messagebox.showerror("Export Error", str(e))

    def export_json(self):
        if not self.devices:
            self.log("No scan data to export. Run a scan first.")
            messagebox.showwarning("Export Failed", "No device data to export.")
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON Files", "*.json")]
        )
        if not filepath:
            return
        try:
            export_to_json(self.devices, filepath)
            self.log(f"Device data exported to JSON: {filepath}")
            messagebox.showinfo("Export Successful", "JSON file saved.")
        except Exception as e:
            self.log(str(e))
            messagebox.showerror("Export Error", str(e))

    def open_settings(self):
        config = load_config()
        scanner_conf = config.get("scanner", {})
        subnet = scanner_conf.get("subnet", "192.168.1.0/24")
        ports = ",".join(str(p) for p in scanner_conf.get("ports", []))

        win = tk.Toplevel(self.root)
        win.title("Scanner Settings")
        win.geometry("300x200")

        tk.Label(win, text="Subnet (CIDR):").pack(pady=5)
        subnet_entry = tk.Entry(win)
        subnet_entry.insert(0, subnet)
        subnet_entry.pack()

        tk.Label(win, text="Ports (comma-separated):").pack(pady=5)
        ports_entry = tk.Entry(win)
        ports_entry.insert(0, ports)
        ports_entry.pack()

        def save_settings():
            new_subnet = subnet_entry.get()
            new_ports = [
                int(p.strip())
                for p in ports_entry.get().split(",")
                if p.strip().isdigit()
            ]
            config["scanner"] = {"subnet": new_subnet, "ports": new_ports}
            save_config(config)
            self.log("Settings saved.")
            win.destroy()

        tk.Button(win, text="Save", command=save_settings).pack(pady=10)

    def is_off_hours(self):
        # Example: Detect only between 22:00 and 06:00
        now = datetime.datetime.now().time()
        return now >= datetime.time(22, 0) or now <= datetime.time(6, 0)

    def intrusion_alert(self, message):
        self.log(f"⚠️ {message}")
        # Optionally popup alert box:
        messagebox.showwarning("Intrusion Alert", message)

    def start_intrusion(self):
        self.log("Starting intrusion detection...")
        self.detector.start_detection()

    def stop_intrusion(self):
        self.log("Stopping intrusion detection...")
        self.detector.stop_detection()


if __name__ == "__main__":
    root = tk.Tk()
    app = GuardianAIGUI(root)
    root.mainloop()
