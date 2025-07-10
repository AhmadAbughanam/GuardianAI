import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from core.scanner import DeviceScanner
from core.log_parser import save_scan_results, fetch_recent_logs, format_for_display
from core.ai_classifier import AIClassifier
from utils.rules import evaluate_all
from utils.export import export_to_csv, export_to_json
from tkinter import filedialog
import yaml
from threading import Thread
import datetime
from core.intrusion_cv import IntrusionDetector
from tkinter import messagebox


def load_config():
    try:
        with open("config.yaml", "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"Error loading config: {e}")
        return {}


def save_config(data):
    try:
        with open("config.yaml", "w") as f:
            yaml.dump(data, f)
    except Exception as e:
        print(f"Error saving config: {e}")


class GuardianAIGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("GuardianAI - Network Security Dashboard")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)

        # Configure modern color scheme
        self.colors = {
            "primary": "#2c3e50",
            "secondary": "#34495e",
            "accent": "#3498db",
            "success": "#27ae60",
            "warning": "#f39c12",
            "danger": "#e74c3c",
            "light": "#ecf0f1",
            "dark": "#2c3e50",
            "bg": "#f8f9fa",
            "card": "#ffffff",
            "text": "#2c3e50",
            "text_light": "#7f8c8d",
        }

        self.devices = []
        self.detector = IntrusionDetector(alert_callback=self.intrusion_alert)
        self.tree_items = []
        self.is_detection_running = False

        self.setup_styles()
        self.setup_widgets()
        self.setup_status_bar()

    def setup_styles(self):
        """Configure modern ttk styles"""
        style = ttk.Style()

        # Configure notebook style for tabs
        style.configure("Custom.TNotebook", background=self.colors["bg"])
        style.configure(
            "Custom.TNotebook.Tab",
            padding=[20, 10],
            font=("Segoe UI", 10),
            focuscolor="none",
        )

        # Configure frame styles
        style.configure(
            "Card.TFrame", background=self.colors["card"], relief="flat", borderwidth=1
        )

        style.configure("Header.TFrame", background=self.colors["primary"])

        # Configure button styles
        style.configure(
            "Primary.TButton", font=("Segoe UI", 10, "bold"), padding=[15, 8]
        )

        style.configure("Success.TButton", font=("Segoe UI", 10), padding=[15, 8])

        style.configure("Warning.TButton", font=("Segoe UI", 10), padding=[15, 8])

        style.configure("Danger.TButton", font=("Segoe UI", 10), padding=[15, 8])

        # Configure treeview style
        style.configure(
            "Custom.Treeview",
            background=self.colors["card"],
            foreground=self.colors["text"],
            fieldbackground=self.colors["card"],
            font=("Segoe UI", 10),
        )

        style.configure(
            "Custom.Treeview.Heading",
            background=self.colors["secondary"],
            foreground="white",
            font=("Segoe UI", 10, "bold"),
        )

    def setup_widgets(self):
        """Setup the main widget layout"""
        # Configure main grid
        self.root.configure(bg=self.colors["bg"])
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Header
        self.setup_header()

        # Main content with notebook
        self.setup_main_content()

        # Status bar will be added later

    def setup_header(self):
        """Create modern header with title and status indicators"""
        header_frame = tk.Frame(self.root, bg=self.colors["primary"], height=80)
        header_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        header_frame.grid_columnconfigure(1, weight=1)
        header_frame.grid_propagate(False)

        # Logo/Icon area
        logo_frame = tk.Frame(header_frame, bg=self.colors["primary"])
        logo_frame.grid(row=0, column=0, padx=20, pady=10, sticky="w")

        # Title
        title_label = tk.Label(
            logo_frame,
            text="🛡️ GuardianAI",
            font=("Segoe UI", 20, "bold"),
            bg=self.colors["primary"],
            fg="white",
        )
        title_label.pack(side="left")

        subtitle_label = tk.Label(
            logo_frame,
            text="Network Security Dashboard",
            font=("Segoe UI", 11),
            bg=self.colors["primary"],
            fg=self.colors["light"],
        )
        subtitle_label.pack(side="left", padx=(10, 0))

        # Status indicators
        status_frame = tk.Frame(header_frame, bg=self.colors["primary"])
        status_frame.grid(row=0, column=2, padx=20, pady=10, sticky="e")

        # Network status
        self.network_status = tk.Label(
            status_frame,
            text="⚪ Network: Idle",
            font=("Segoe UI", 10),
            bg=self.colors["primary"],
            fg=self.colors["light"],
        )
        self.network_status.pack(anchor="e")

        # Detection status
        self.detection_status = tk.Label(
            status_frame,
            text="⚪ Detection: Stopped",
            font=("Segoe UI", 10),
            bg=self.colors["primary"],
            fg=self.colors["light"],
        )
        self.detection_status.pack(anchor="e")

    def setup_main_content(self):
        """Create main content area with notebook tabs"""
        # Main container
        main_frame = tk.Frame(self.root, bg=self.colors["bg"])
        main_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)

        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame, style="Custom.TNotebook")
        self.notebook.grid(row=0, column=0, sticky="nsew")

        # Dashboard tab
        self.setup_dashboard_tab()

        # Devices tab
        self.setup_devices_tab()

        # Logs tab
        self.setup_logs_tab()

        # Settings tab
        self.setup_settings_tab()

    def setup_dashboard_tab(self):
        """Create dashboard overview tab"""
        dashboard_frame = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.notebook.add(dashboard_frame, text="📊 Dashboard")

        dashboard_frame.grid_rowconfigure(1, weight=1)
        dashboard_frame.grid_columnconfigure((0, 1), weight=1)

        # Quick stats cards
        stats_frame = tk.Frame(dashboard_frame, bg=self.colors["bg"])
        stats_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        # Stats cards
        self.devices_card = self.create_stat_card(stats_frame, "Devices", "0", "🖥️", 0)
        self.threats_card = self.create_stat_card(stats_frame, "Threats", "0", "⚠️", 1)
        self.scans_card = self.create_stat_card(stats_frame, "Scans", "0", "🔍", 2)
        self.alerts_card = self.create_stat_card(stats_frame, "Alerts", "0", "🚨", 3)

        # Quick actions panel
        actions_frame = ttk.LabelFrame(
            dashboard_frame, text="Quick Actions", style="Card.TFrame", padding=20
        )
        actions_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        actions_frame.grid_columnconfigure((0, 1), weight=1)

        # Primary action buttons
        ttk.Button(
            actions_frame,
            text="🔍 Start Network Scan",
            command=self.run_scan,
            style="Primary.TButton",
        ).grid(row=0, column=0, columnspan=2, sticky="ew", pady=5)

        ttk.Button(
            actions_frame,
            text="▶️ Start Detection",
            command=self.start_intrusion,
            style="Success.TButton",
        ).grid(row=1, column=0, sticky="ew", padx=(0, 5), pady=5)

        ttk.Button(
            actions_frame,
            text="⏹ Stop Detection",
            command=self.stop_intrusion,
            style="Danger.TButton",
        ).grid(row=1, column=1, sticky="ew", padx=(5, 0), pady=5)

        ttk.Button(
            actions_frame,
            text="🧠 AI Analysis",
            command=self.classify_logs,
            style="Warning.TButton",
        ).grid(row=2, column=0, sticky="ew", padx=(0, 5), pady=5)

        ttk.Button(
            actions_frame,
            text="🛡️ Security Check",
            command=self.run_security_check,
            style="Warning.TButton",
        ).grid(row=2, column=1, sticky="ew", padx=(5, 0), pady=5)

        # Recent activity panel
        activity_frame = ttk.LabelFrame(
            dashboard_frame, text="Recent Activity", style="Card.TFrame", padding=20
        )
        activity_frame.grid(row=1, column=1, sticky="nsew", padx=10, pady=5)
        activity_frame.grid_rowconfigure(0, weight=1)
        activity_frame.grid_columnconfigure(0, weight=1)

        self.activity_text = scrolledtext.ScrolledText(
            activity_frame,
            height=15,
            wrap=tk.WORD,
            state="disabled",
            bg=self.colors["card"],
            fg=self.colors["text"],
            font=("Consolas", 10),
        )
        self.activity_text.grid(row=0, column=0, sticky="nsew")

    def create_stat_card(self, parent, title, value, icon, column):
        """Create a statistics card"""
        card = tk.Frame(parent, bg=self.colors["card"], relief="flat", bd=1)
        card.grid(row=0, column=column, sticky="ew", padx=5, pady=5)

        # Add border effect
        border = tk.Frame(card, bg=self.colors["accent"], height=3)
        border.pack(fill="x", side="top")

        content = tk.Frame(card, bg=self.colors["card"])
        content.pack(fill="both", expand=True, padx=15, pady=15)

        # Icon and title
        header = tk.Frame(content, bg=self.colors["card"])
        header.pack(fill="x")

        icon_label = tk.Label(
            header,
            text=icon,
            font=("Segoe UI", 16),
            bg=self.colors["card"],
            fg=self.colors["accent"],
        )
        icon_label.pack(side="left")

        title_label = tk.Label(
            header,
            text=title,
            font=("Segoe UI", 10, "bold"),
            bg=self.colors["card"],
            fg=self.colors["text"],
        )
        title_label.pack(side="left", padx=(10, 0))

        # Value
        value_label = tk.Label(
            content,
            text=value,
            font=("Segoe UI", 24, "bold"),
            bg=self.colors["card"],
            fg=self.colors["text"],
        )
        value_label.pack(anchor="w", pady=(5, 0))

        return value_label

    def setup_devices_tab(self):
        """Create devices management tab"""
        devices_frame = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.notebook.add(devices_frame, text="🖥️ Devices")

        devices_frame.grid_rowconfigure(1, weight=1)
        devices_frame.grid_columnconfigure(0, weight=1)

        # Toolbar
        toolbar_frame = tk.Frame(devices_frame, bg=self.colors["bg"])
        toolbar_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
        toolbar_frame.grid_columnconfigure(4, weight=1)

        ttk.Button(toolbar_frame, text="🔄 Refresh", command=self.run_scan).grid(
            row=0, column=0, padx=5
        )
        ttk.Button(toolbar_frame, text="💾 Save", command=self.save_logs).grid(
            row=0, column=1, padx=5
        )
        ttk.Button(toolbar_frame, text="📤 Export CSV", command=self.export_csv).grid(
            row=0, column=2, padx=5
        )
        ttk.Button(toolbar_frame, text="📤 Export JSON", command=self.export_json).grid(
            row=0, column=3, padx=5
        )

        # Search frame
        search_frame = tk.Frame(toolbar_frame, bg=self.colors["bg"])
        search_frame.grid(row=0, column=5, sticky="e", padx=5)

        tk.Label(
            search_frame, text="Search:", bg=self.colors["bg"], fg=self.colors["text"]
        ).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(
            search_frame, textvariable=self.search_var, width=20
        )
        self.search_entry.pack(side="left", padx=(5, 0))
        self.search_var.trace("w", self.filter_devices)

        # Device list frame
        list_frame = tk.Frame(devices_frame, bg=self.colors["bg"])
        list_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        # Enhanced treeview
        self.tree = ttk.Treeview(
            list_frame,
            columns=("IP", "MAC", "Hostname", "Open Ports", "Status", "Risk"),
            show="headings",
            style="Custom.Treeview",
        )

        # Configure columns
        columns = [
            ("IP", "IP Address", 130),
            ("MAC", "MAC Address", 150),
            ("Hostname", "Hostname", 150),
            ("Open Ports", "Open Ports", 200),
            ("Status", "Status", 100),
            ("Risk", "Risk Level", 100),
        ]

        for col, heading, width in columns:
            self.tree.heading(col, text=heading)
            self.tree.column(col, width=width, anchor=tk.W)

        # Scrollbars
        v_scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        h_scroll = ttk.Scrollbar(
            list_frame, orient="horizontal", command=self.tree.xview
        )
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")

        # Configure row colors
        self.tree.tag_configure("high", background="#ffebee")
        self.tree.tag_configure("medium", background="#fff3e0")
        self.tree.tag_configure("low", background="#e8f5e8")
        self.tree.tag_configure("safe", background="#f3e5f5")

        # Bind events
        self.tree.bind("<Button-3>", self.show_device_context_menu)
        self.tree.bind("<Double-1>", self.show_device_details)

    def setup_logs_tab(self):
        """Create logs and monitoring tab"""
        logs_frame = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.notebook.add(logs_frame, text="📜 Logs")

        logs_frame.grid_rowconfigure(1, weight=1)
        logs_frame.grid_columnconfigure(0, weight=1)

        # Log controls
        controls_frame = tk.Frame(logs_frame, bg=self.colors["bg"])
        controls_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=5)

        ttk.Button(
            controls_frame, text="📜 Load Recent", command=self.show_recent_logs
        ).pack(side="left", padx=5)
        ttk.Button(controls_frame, text="🧹 Clear", command=self.clear_logs).pack(
            side="left", padx=5
        )
        ttk.Button(controls_frame, text="💾 Save", command=self.save_logs_to_file).pack(
            side="left", padx=5
        )

        # Auto-scroll checkbox
        self.auto_scroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            controls_frame, text="Auto-scroll", variable=self.auto_scroll
        ).pack(side="right", padx=5)

        # Log display
        log_container = tk.Frame(logs_frame, bg=self.colors["bg"])
        log_container.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        log_container.grid_rowconfigure(0, weight=1)
        log_container.grid_columnconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(
            log_container,
            wrap=tk.WORD,
            state="disabled",
            bg=self.colors["card"],
            fg=self.colors["text"],
            font=("Consolas", 10),
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")

        # Configure log text tags for different message types
        self.log_text.tag_configure("info", foreground=self.colors["text"])
        self.log_text.tag_configure("warning", foreground=self.colors["warning"])
        self.log_text.tag_configure("error", foreground=self.colors["danger"])
        self.log_text.tag_configure("success", foreground=self.colors["success"])

    def setup_settings_tab(self):
        """Create settings and configuration tab"""
        settings_frame = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.notebook.add(settings_frame, text="⚙️ Settings")

        # Create scrollable frame for settings
        canvas = tk.Canvas(settings_frame, bg=self.colors["bg"])
        scrollbar = ttk.Scrollbar(
            settings_frame, orient="vertical", command=canvas.yview
        )
        scrollable_frame = tk.Frame(canvas, bg=self.colors["bg"])

        scrollable_frame.bind(
            "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Scanner settings
        scanner_frame = ttk.LabelFrame(
            scrollable_frame, text="Scanner Configuration", padding=20
        )
        scanner_frame.pack(fill="x", padx=10, pady=10)

        # Load current config
        config = load_config()
        scanner_conf = config.get("scanner", {})

        # Subnet setting
        tk.Label(scanner_frame, text="Network Subnet:", bg=self.colors["bg"]).grid(
            row=0, column=0, sticky="w", pady=5
        )
        self.subnet_var = tk.StringVar(
            value=scanner_conf.get("subnet", "192.168.1.0/24")
        )
        ttk.Entry(scanner_frame, textvariable=self.subnet_var, width=30).grid(
            row=0, column=1, sticky="ew", padx=10, pady=5
        )

        # Ports setting
        tk.Label(scanner_frame, text="Scan Ports:", bg=self.colors["bg"]).grid(
            row=1, column=0, sticky="w", pady=5
        )
        ports_str = ",".join(
            str(p) for p in scanner_conf.get("ports", [22, 80, 443, 8080])
        )
        self.ports_var = tk.StringVar(value=ports_str)
        ttk.Entry(scanner_frame, textvariable=self.ports_var, width=30).grid(
            row=1, column=1, sticky="ew", padx=10, pady=5
        )

        # Timeout setting
        tk.Label(scanner_frame, text="Timeout (seconds):", bg=self.colors["bg"]).grid(
            row=2, column=0, sticky="w", pady=5
        )
        self.timeout_var = tk.StringVar(value=str(scanner_conf.get("timeout", 1)))
        ttk.Entry(scanner_frame, textvariable=self.timeout_var, width=30).grid(
            row=2, column=1, sticky="ew", padx=10, pady=5
        )

        scanner_frame.grid_columnconfigure(1, weight=1)

        # Detection settings
        detection_frame = ttk.LabelFrame(
            scrollable_frame, text="Detection Settings", padding=20
        )
        detection_frame.pack(fill="x", padx=10, pady=10)

        # Alert settings
        self.email_alerts = tk.BooleanVar(value=config.get("email_alerts", False))
        ttk.Checkbutton(
            detection_frame, text="Enable Email Alerts", variable=self.email_alerts
        ).grid(row=0, column=0, sticky="w", pady=5)

        self.sound_alerts = tk.BooleanVar(value=config.get("sound_alerts", True))
        ttk.Checkbutton(
            detection_frame, text="Enable Sound Alerts", variable=self.sound_alerts
        ).grid(row=1, column=0, sticky="w", pady=5)

        # Save button
        ttk.Button(
            scrollable_frame,
            text="💾 Save Settings",
            command=self.save_settings,
            style="Primary.TButton",
        ).pack(pady=20)

    def setup_status_bar(self):
        """Create status bar at the bottom"""
        self.status_bar = tk.Frame(self.root, bg=self.colors["secondary"], height=25)
        self.status_bar.grid(row=2, column=0, sticky="ew")
        self.status_bar.grid_propagate(False)

        self.status_text = tk.Label(
            self.status_bar,
            text="Ready",
            bg=self.colors["secondary"],
            fg="white",
            font=("Segoe UI", 9),
        )
        self.status_text.pack(side="left", padx=10, pady=3)

        # Time display
        self.time_label = tk.Label(
            self.status_bar,
            text="",
            bg=self.colors["secondary"],
            fg="white",
            font=("Segoe UI", 9),
        )
        self.time_label.pack(side="right", padx=10, pady=3)

        self.update_time()

    def update_time(self):
        """Update the time display"""
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)

    def filter_devices(self, *args):
        """Filter devices based on search term"""
        search_term = self.search_var.get().lower()

        # Clear current items
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Re-populate with filtered items
        for dev in self.devices:
            if (
                search_term in dev.get("ip", "").lower()
                or search_term in dev.get("mac", "").lower()
                or search_term in dev.get("hostname", "").lower()
            ):

                self.tree.insert(
                    "",
                    "end",
                    values=(
                        dev["ip"],
                        dev["mac"],
                        dev["hostname"] or "Unknown",
                        ", ".join(str(p) for p in dev["open_ports"]),
                        "Active",
                        "Low",
                    ),
                )

    def show_device_context_menu(self, event):
        """Show context menu for device"""
        item = self.tree.identify_row(event.y)
        if not item:
            return

        self.tree.selection_set(item)
        item_data = self.tree.item(item, "values")
        if not item_data:
            return

        context_menu = tk.Menu(self.root, tearoff=0)
        context_menu.add_command(
            label="🔍 Device Details", command=lambda: self.show_device_details(None)
        )
        context_menu.add_command(
            label="✅ Mark as Safe", command=lambda: self.mark_device_safe(item_data)
        )
        context_menu.add_command(
            label="⚠️ Mark as Suspicious",
            command=lambda: self.mark_device_suspicious(item_data),
        )
        context_menu.add_separator()
        context_menu.add_command(
            label="🚫 Block Device", command=lambda: self.block_device(item_data)
        )

        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()

    def show_device_details(self, event):
        """Show detailed device information"""
        selection = self.tree.selection()
        if not selection:
            return

        item_data = self.tree.item(selection[0], "values")
        if not item_data:
            return

        # Create details window
        details_window = tk.Toplevel(self.root)
        details_window.title("Device Details")
        details_window.geometry("500x400")
        details_window.transient(self.root)
        details_window.grab_set()

        # Device info
        info_frame = ttk.LabelFrame(
            details_window, text="Device Information", padding=15
        )
        info_frame.pack(fill="x", padx=10, pady=10)

        details = [
            ("IP Address:", item_data[0]),
            ("MAC Address:", item_data[1]),
            ("Hostname:", item_data[2]),
            ("Open Ports:", item_data[3]),
            ("Status:", item_data[4]),
            ("Risk Level:", item_data[5]),
        ]

        for i, (label, value) in enumerate(details):
            tk.Label(info_frame, text=label, font=("Segoe UI", 10, "bold")).grid(
                row=i, column=0, sticky="w", pady=5
            )
            tk.Label(info_frame, text=value, font=("Segoe UI", 10)).grid(
                row=i, column=1, sticky="w", padx=20, pady=5
            )

    def mark_device_safe(self, item_data):
        """Mark device as safe"""
        ip, mac = item_data[0], item_data[1]
        config = load_config()
        whitelist = config.get("whitelist", {"mac": [], "ip": []})

        if mac and mac not in whitelist["mac"]:
            whitelist["mac"].append(mac.upper())
        if ip and ip not in whitelist["ip"]:
            whitelist["ip"].append(ip)

        config["whitelist"] = whitelist
        save_config(config)

        self.log_message(f"Device {ip} ({mac}) marked as safe", "success")
        messagebox.showinfo("Success", f"Device {ip} has been whitelisted")

    def mark_device_suspicious(self, item_data):
        """Mark device as suspicious"""
        ip = item_data[0]
        self.log_message(f"Device {ip} marked as suspicious", "warning")
        messagebox.showwarning("Marked", f"Device {ip} marked as suspicious")

    def block_device(self, item_data):
        """Block device"""
        ip = item_data[0]
        confirm = messagebox.askyesno(
            "Confirm Block", f"Are you sure you want to block device {ip}?"
        )
        if confirm:
            self.log_message(f"Device {ip} blocked", "error")
            messagebox.showinfo("Blocked", f"Device {ip} has been blocked")

    def log_message(self, message, level="info"):
        """Add message to log with timestamp and level"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"

        # Add to activity log
        self.activity_text.config(state="normal")
        self.activity_text.insert(tk.END, formatted_message, level)
        if self.auto_scroll.get():
            self.activity_text.see(tk.END)
        self.activity_text.config(state="disabled")

        # Add to main log
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, formatted_message, level)
        if self.auto_scroll.get():
            self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

        # Update status bar
        self.status_text.config(text=message)

    def clear_logs(self):
        """Clear all log displays"""
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state="disabled")

        self.activity_text.config(state="normal")
        self.activity_text.delete("1.0", tk.END)
        self.activity_text.config(state="disabled")

        self.log_message("Logs cleared", "info")

    def save_logs_to_file(self):
        """Save logs to file"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Save Logs",
        )

        if filepath:
            try:
                with open(filepath, "w") as f:
                    f.write(self.log_text.get("1.0", tk.END))
                self.log_message(f"Logs saved to {filepath}", "success")
            except Exception as e:
                self.log_message(f"Error saving logs: {str(e)}", "error")

    def save_settings(self):
        """Save configuration settings"""
        try:
            config = load_config()

            # Scanner settings
            subnet = self.subnet_var.get().strip()
            ports_str = self.ports_var.get().strip()
            timeout = int(self.timeout_var.get())

            # Validate subnet
            if not subnet or "/" not in subnet:
                messagebox.showerror("Error", "Invalid subnet format")
                return

            # Parse ports
            ports = []
            if ports_str:
                try:
                    ports = [
                        int(p.strip())
                        for p in ports_str.split(",")
                        if p.strip().isdigit()
                    ]
                except ValueError:
                    messagebox.showerror("Error", "Invalid ports format")
                    return

            # Update config
            config["scanner"] = {"subnet": subnet, "ports": ports, "timeout": timeout}

            config["email_alerts"] = self.email_alerts.get()
            config["sound_alerts"] = self.sound_alerts.get()

            save_config(config)
            self.log_message("Settings saved successfully", "success")
            messagebox.showinfo("Success", "Settings saved successfully")

        except Exception as e:
            self.log_message(f"Error saving settings: {str(e)}", "error")
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")

    def update_stats(self):
        """Update dashboard statistics"""
        device_count = len(self.devices)
        self.devices_card.config(text=str(device_count))

        # Update network status
        if device_count > 0:
            self.network_status.config(
                text="🟢 Network: Active", fg=self.colors["success"]
            )
        else:
            self.network_status.config(text="⚪ Network: Idle", fg=self.colors["light"])

    def run_scan(self):
        """Run network scan with enhanced UI feedback"""
        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.devices = []
        self.tree_items = []

        # Update UI state
        self.log_message("Starting network scan...", "info")
        self.network_status.config(
            text="🔄 Network: Scanning...", fg=self.colors["warning"]
        )

        def scan_thread():
            try:
                scanner = DeviceScanner()
                self.devices = scanner.full_scan()

                if not self.devices:
                    self.log_message("No devices found on network", "warning")
                    self.network_status.config(
                        text="⚪ Network: No devices", fg=self.colors["light"]
                    )
                    return

                # Update UI from main thread
                self.root.after(0, self.populate_device_list)

            except Exception as e:
                error_msg = f"Scan error: {str(e)}"
                self.root.after(0, lambda: self.log_message(error_msg, "error"))
                self.root.after(
                    0,
                    lambda: self.network_status.config(
                        text="🔴 Network: Error", fg=self.colors["danger"]
                    ),
                )

        Thread(target=scan_thread, daemon=True).start()

    def populate_device_list(self):
        """Populate the device list in the UI"""
        for dev in self.devices:
            # Determine risk level based on open ports
            risk_level = "Low"
            if len(dev["open_ports"]) > 5:
                risk_level = "High"
            elif len(dev["open_ports"]) > 2:
                risk_level = "Medium"

            # Add to tree
            item = self.tree.insert(
                "",
                "end",
                values=(
                    dev["ip"],
                    dev["mac"],
                    dev["hostname"] or "Unknown",
                    ", ".join(str(p) for p in dev["open_ports"]),
                    "Active",
                    risk_level,
                ),
            )

            # Apply color coding
            if risk_level == "High":
                self.tree.item(item, tags=("high",))
            elif risk_level == "Medium":
                self.tree.item(item, tags=("medium",))
            else:
                self.tree.item(item, tags=("low",))

            self.tree_items.append((item, dev))

        # Update statistics and status
        self.update_stats()
        self.log_message(f"Scan complete. Found {len(self.devices)} devices", "success")
        self.network_status.config(text="🟢 Network: Active", fg=self.colors["success"])

    def save_logs(self):
        """Save scan results to database"""
        if not self.devices:
            self.log_message("No scan results to save", "warning")
            messagebox.showwarning("Nothing to Save", "Run a scan before saving logs")
            return

        try:
            save_scan_results(self.devices)
            self.log_message("Scan results saved to database", "success")
            messagebox.showinfo("Success", "Scan logs saved successfully")
        except Exception as e:
            error_msg = f"Error saving logs: {str(e)}"
            self.log_message(error_msg, "error")
            messagebox.showerror("Save Error", str(e))

    def show_recent_logs(self):
        """Show recent logs from database"""
        try:
            logs = fetch_recent_logs(limit=20)
            if not logs:
                self.log_message("No previous logs found in database", "info")
                return

            self.log_message("=== Recent Database Logs ===", "info")
            for log_entry in logs:
                formatted_log = format_for_display(log_entry)
                self.log_message(formatted_log, "info")
            self.log_message("=== End of Database Logs ===", "info")

        except Exception as e:
            error_msg = f"Error fetching logs: {str(e)}"
            self.log_message(error_msg, "error")
            messagebox.showerror("Load Error", str(e))

    def classify_logs(self):
        """Run AI classification on devices"""
        if not self.devices:
            self.log_message("No devices to classify. Run a scan first.", "warning")
            messagebox.showwarning(
                "No Devices", "Please run a scan before AI classification"
            )
            return

        def classify_thread():
            try:
                self.root.after(
                    0, lambda: self.log_message("Starting AI classification...", "info")
                )
                classifier = AIClassifier()

                for idx, (item, dev) in enumerate(self.tree_items):
                    result = classifier.classify(dev)
                    severity = result.get("severity", "Unknown")
                    recommendation = result.get("recommendation", "No recommendation")

                    # Update UI from main thread
                    self.root.after(
                        0,
                        lambda s=severity, r=recommendation, ip=dev[
                            "ip"
                        ]: self.log_message(
                            f"[{ip}] AI Classification: {s} - {r}", "info"
                        ),
                    )

                    # Update tree item color
                    if severity == "High":
                        self.root.after(
                            0, lambda i=item: self.tree.item(i, tags=("high",))
                        )
                    elif severity == "Medium":
                        self.root.after(
                            0, lambda i=item: self.tree.item(i, tags=("medium",))
                        )
                    else:
                        self.root.after(
                            0, lambda i=item: self.tree.item(i, tags=("low",))
                        )

                self.root.after(
                    0, lambda: self.log_message("AI classification complete", "success")
                )

            except Exception as e:
                error_msg = f"AI classification error: {str(e)}"
                self.root.after(0, lambda: self.log_message(error_msg, "error"))
                self.root.after(0, lambda: messagebox.showerror("AI Error", str(e)))

        Thread(target=classify_thread, daemon=True).start()

    def run_security_check(self):
        """Run rule-based security analysis"""
        if not self.devices:
            self.log_message("No devices to analyze. Run a scan first.", "warning")
            messagebox.showwarning("No Devices", "Run a scan before security check")
            return

        def security_thread():
            try:
                self.root.after(
                    0, lambda: self.log_message("Running security analysis...", "info")
                )
                issues = evaluate_all(self.devices)

                if not issues:
                    self.root.after(
                        0,
                        lambda: self.log_message(
                            "✅ No security issues detected", "success"
                        ),
                    )
                    return

                threat_count = 0
                for issue in issues:
                    threat_count += 1
                    ip = issue["ip"]
                    severity = issue["severity"]
                    description = issue["issue"]

                    # Log the issue
                    self.root.after(
                        0,
                        lambda i=ip, s=severity, d=description: self.log_message(
                            f"[{i}] {d} (Severity: {s})", "warning"
                        ),
                    )

                    # Update tree item
                    for item, dev in self.tree_items:
                        if dev["ip"] == ip:
                            if severity == "High":
                                self.root.after(
                                    0, lambda i=item: self.tree.item(i, tags=("high",))
                                )
                            elif severity == "Medium":
                                self.root.after(
                                    0,
                                    lambda i=item: self.tree.item(i, tags=("medium",)),
                                )

                # Update threat count
                self.root.after(
                    0, lambda: self.threats_card.config(text=str(threat_count))
                )
                self.root.after(
                    0,
                    lambda: self.log_message(
                        f"🛡️ Security analysis complete. {threat_count} issues found",
                        "warning",
                    ),
                )

            except Exception as e:
                error_msg = f"Security check error: {str(e)}"
                self.root.after(0, lambda: self.log_message(error_msg, "error"))
                self.root.after(
                    0, lambda: messagebox.showerror("Security Error", str(e))
                )

        Thread(target=security_thread, daemon=True).start()

    def export_csv(self):
        """Export devices to CSV"""
        if not self.devices:
            self.log_message("No scan data to export", "warning")
            messagebox.showwarning("Export Failed", "No device data to export")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title="Export Devices to CSV",
        )

        if filepath:
            try:
                export_to_csv(self.devices, filepath)
                self.log_message(f"Device data exported to CSV: {filepath}", "success")
                messagebox.showinfo("Export Successful", "CSV file saved successfully")
            except Exception as e:
                error_msg = f"Export error: {str(e)}"
                self.log_message(error_msg, "error")
                messagebox.showerror("Export Error", str(e))

    def export_json(self):
        """Export devices to JSON"""
        if not self.devices:
            self.log_message("No scan data to export", "warning")
            messagebox.showwarning("Export Failed", "No device data to export")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")],
            title="Export Devices to JSON",
        )

        if filepath:
            try:
                export_to_json(self.devices, filepath)
                self.log_message(f"Device data exported to JSON: {filepath}", "success")
                messagebox.showinfo("Export Successful", "JSON file saved successfully")
            except Exception as e:
                error_msg = f"Export error: {str(e)}"
                self.log_message(error_msg, "error")
                messagebox.showerror("Export Error", str(e))

    def start_intrusion(self):
        """Start intrusion detection"""
        if self.is_detection_running:
            self.log_message("Intrusion detection is already running", "warning")
            return

        try:
            self.detector.start_detection()
            self.is_detection_running = True
            self.detection_status.config(
                text="🟢 Detection: Running", fg=self.colors["success"]
            )
            self.log_message("Intrusion detection started", "success")
        except Exception as e:
            error_msg = f"Failed to start intrusion detection: {str(e)}"
            self.log_message(error_msg, "error")
            messagebox.showerror("Detection Error", str(e))

    def stop_intrusion(self):
        """Stop intrusion detection"""
        if not self.is_detection_running:
            self.log_message("Intrusion detection is not running", "warning")
            return

        try:
            self.detector.stop_detection()
            self.is_detection_running = False
            self.detection_status.config(
                text="⚪ Detection: Stopped", fg=self.colors["light"]
            )
            self.log_message("Intrusion detection stopped", "info")
        except Exception as e:
            error_msg = f"Failed to stop intrusion detection: {str(e)}"
            self.log_message(error_msg, "error")
            messagebox.showerror("Detection Error", str(e))

    def intrusion_alert(self, message):
        """Handle intrusion alerts"""
        alert_msg = f"⚠️ INTRUSION ALERT: {message}"
        self.log_message(alert_msg, "error")

        # Update alert count
        current_alerts = int(self.alerts_card.cget("text"))
        self.alerts_card.config(text=str(current_alerts + 1))

        # Show popup if sound alerts are enabled
        config = load_config()
        if config.get("sound_alerts", True):
            self.root.bell()  # System beep

        # Show warning dialog
        messagebox.showwarning("Intrusion Alert", message)

    def is_off_hours(self):
        """Check if current time is during off hours"""
        now = datetime.datetime.now().time()
        return now >= datetime.time(22, 0) or now <= datetime.time(6, 0)

    # Legacy method for backward compatibility
    def log(self, message):
        """Legacy logging method"""
        self.log_message(message, "info")

    def right_click(self, event):
        """Legacy right-click handler"""
        self.show_device_context_menu(event)

    def open_settings(self):
        """Legacy settings method - switch to settings tab"""
        self.notebook.select(3)  # Select settings tab


if __name__ == "__main__":
    root = tk.Tk()
    app = GuardianAIGUI(root)
    root.mainloop()
