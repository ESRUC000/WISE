"""Frontend"""

import queue
import threading
import tkinter as tk
import csv
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog, ttk
import api_client as database
from channel_check import get_channel_status
from security_score import compare_scores, score_connection


# Shared visual theme: deep navy, cool neutral surfaces, and clear risk colors.
BG = "#F4F7FB"
SURFACE = "#FFFFFF"
SURFACE_ALT = "#F8FAFD"
NAVY = "#14233B"
NAVY_2 = "#1C3151"
INK = "#1B2A41"
MUTED = "#718096"
LINE = "#E3EAF2"
BLUE = "#3478F6"
BLUE_DARK = "#2464DE"
BLUE_PALE = "#EAF2FF"
GREEN = "#16865C"
GREEN_PALE = "#EAF7F0"
AMBER = "#9A5B00"
AMBER_PALE = "#FFF5E3"
RED = "#B42332"
RED_PALE = "#FFF0F0"


class WiseApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WISE | Wi-Fi Security")
        self.geometry("1200x820")
        self.minsize(1000, 700)
        self.configure(bg=BG)

        self.connection = None
        self.score_info = None
        self.latest_scan_id = None
        self.separate_scan_history_var = tk.BooleanVar(value=False)
        self.admin_password_var = tk.BooleanVar(value=False)
        self.password_var = tk.BooleanVar(value=False)
        self.current_page = "dashboard"
        self.scan_animation_id = None
        self.score_animation_id = None
        self.score_ring_value = 0
        self.score_rows = {}
        self.history_rows = []
        self.nav_buttons = {}
        self.viewing_saved_scan = False
        self.details_source_var = tk.StringVar(value="CURRENT INTERFACE + ANALYZER")
        self.scan_session = 0
        self.scan_events = queue.Queue()
        self.scan_poll_id = None
        self.api_generation = 0
        self.device_session = 0
        self.latest_device_snapshot = None
        self.bar_animation_ids = []
        self.closing = False
        self.user = None

        self.database_start_error = None
        try:
            database.initialize_database()
        except Exception as error:
            # Keep the UI usable even when history storage cannot be opened.
            self.database_start_error = str(error)
        self._setup_style()
        self._build_shell()
        self._build_dashboard()
        self._build_history()
        self._build_devices()
        self._build_reports()
        self._build_account_settings()
        self._build_auth()
        self.show_page("dashboard")
        self._show_auth()
        self.protocol("WM_DELETE_WINDOW", self._close_app)
        self.scan_poll_id = self.after(60, self._process_scan_events)
        if self.database_start_error:
            self.status_var.set(f"History database unavailable: {self.database_start_error}")

    def _setup_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Wise.Treeview", background=SURFACE, fieldbackground=SURFACE,
            foreground=INK, rowheight=39, borderwidth=0,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Wise.Treeview.Heading", background=SURFACE_ALT, foreground=MUTED,
            font=("Segoe UI Semibold", 9), relief="flat", padding=(9, 10),
        )
        style.map("Wise.Treeview", background=[("selected", BLUE_PALE)], foreground=[("selected", INK)])
        style.configure(
            "Wise.Horizontal.TProgressbar", troughcolor="#EAF0F6", background=BLUE,
            bordercolor="#EAF0F6", lightcolor=BLUE, darkcolor=BLUE, thickness=8,
        )

    def _build_shell(self):
        self.sidebar = tk.Frame(self, bg=NAVY, width=218)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        brand = tk.Frame(self.sidebar, bg=NAVY, padx=22, pady=23)
        brand.pack(fill="x")
        mark = tk.Canvas(brand, width=34, height=34, bg=NAVY, highlightthickness=0)
        mark.pack(side="left")
        tk.Label(brand, text="WISE", bg=NAVY, fg="white", font=("Segoe UI", 20, "bold")).pack(side="left", padx=(9, 0))
        tk.Label(self.sidebar, text="WI-FI SECURITY", bg=NAVY, fg="#8293AA",
                 font=("Segoe UI Semibold", 8)).pack(anchor="w", padx=23, pady=(16, 9))

        self._nav_button("dashboard", "◉", "Overview")
        self._nav_button("devices", "⌘", "Devices")
        self._nav_button("history", "◷", "Scan history")
        self._nav_button("reports", "▤", "Reports")
        self._nav_button("account", "⚙", "Account settings")
        self._nav_button("account", "⚙", "Account settings")
        tk.Button(self.sidebar, text="  ↪     Log out", command=self.logout, anchor="w",
                  relief="flat", bd=0, padx=15, pady=12, cursor="hand2", bg=NAVY,
                  fg="#AFC0D6", activebackground=NAVY_2, activeforeground="white",
                  font=("Segoe UI Semibold", 9)).pack(fill="x", padx=12, pady=2)

        spacer = tk.Frame(self.sidebar, bg=NAVY)
        spacer.pack(fill="both", expand=True)
        side_info = tk.Frame(self.sidebar, bg=NAVY_2, padx=13, pady=12)
        side_info.pack(fill="x", padx=13, pady=15)
        tk.Label(side_info, text="ACCOUNT HISTORY", bg=NAVY_2, fg="#C6D6EC",
                 font=("Segoe UI Semibold", 8)).pack(anchor="w")
        tk.Label(side_info, text="Your scans are stored by the WISE server.", bg=NAVY_2, fg="#9EB0C8",
                 wraplength=165, justify="left", font=("Segoe UI", 8)).pack(anchor="w", pady=(5, 0))

        self.main_area = tk.Frame(self, bg=BG)
        self.main_area.pack(side="left", fill="both", expand=True)
        self.topbar = tk.Frame(self.main_area, bg=SURFACE, height=64,
                               highlightbackground=LINE, highlightthickness=1)
        self.topbar.pack(fill="x")
        self.topbar.pack_propagate(False)
        self.breadcrumb_var = tk.StringVar(value="Overview")
        tk.Label(self.topbar, textvariable=self.breadcrumb_var, bg=SURFACE, fg=INK,
                 font=("Segoe UI Semibold", 10)).pack(side="left", padx=25)
        self.connection_badge = tk.Label(self.topbar, text="●  Not scanned", bg=SURFACE_ALT, fg=MUTED,
                                         padx=11, pady=6, font=("Segoe UI Semibold", 8))
        self.connection_badge.pack(side="right", padx=23)

        self.page_host = tk.Frame(self.main_area, bg=BG)
        self.page_host.pack(fill="both", expand=True, padx=25, pady=21)
        self.dashboard = tk.Frame(self.page_host, bg=BG)
        self.history = tk.Frame(self.page_host, bg=BG)
        self.devices = tk.Frame(self.page_host, bg=BG)
        self.reports = tk.Frame(self.page_host, bg=BG)
        self.account = tk.Frame(self.page_host, bg=BG)

        self.status_var = tk.StringVar(value="Ready when you are. Scan to check your connected Wi-Fi.")
        footer = tk.Frame(self.main_area, bg=BG, padx=25, pady=7)
        footer.pack(fill="x", side="bottom")
        tk.Label(footer, textvariable=self.status_var, bg=BG, fg=MUTED,
                 font=("Segoe UI", 8), anchor="w").pack(fill="x")

    def _build_auth(self):
        self.auth_frame = tk.Frame(self, bg=BG)
        card = tk.Frame(self.auth_frame, bg=SURFACE, padx=38, pady=34,
                        highlightbackground=LINE, highlightthickness=1)
        card.place(relx=.5, rely=.5, anchor="center", width=430)
        tk.Label(card, text="WISE", bg=SURFACE, fg=NAVY, font=("Segoe UI", 25, "bold")).pack(anchor="w")
        tk.Label(card, text="Sign in to access your Wi-Fi scan history from the WISE server.", bg=SURFACE,
                 fg=MUTED, wraplength=340, justify="left", font=("Segoe UI", 9)).pack(anchor="w", pady=(5, 21))
        self.auth_server_var = tk.StringVar(value=database.SERVER_URL)
        self.auth_server_detail_var = tk.StringVar(value=f"Server: {database.SERVER_URL}")
        self.configure_button = tk.Button(
            card, text="Configure ▸", command=self._toggle_configure,
            bg=SURFACE, fg=BLUE, relief="flat", anchor="w", cursor="hand2",
            font=("Segoe UI Semibold", 9), padx=0,
        )
        self.configure_button.pack(anchor="w", pady=(0, 3))
        self.configure_frame = tk.LabelFrame(card, text="Configure", bg=SURFACE, fg=INK,
                                             font=("Segoe UI Semibold", 9), padx=10, pady=7)
        tk.Label(self.configure_frame, text="WISE server URL", bg=SURFACE, fg=MUTED).pack(anchor="w")
        self.auth_server_entry = tk.Entry(self.configure_frame, textvariable=self.auth_server_var,
                          font=("Segoe UI", 10), relief="solid", bd=1)
        self.auth_server_entry.pack(fill="x", ipady=6, pady=(4, 4))
        tk.Label(self.configure_frame, textvariable=self.auth_server_detail_var, bg=SURFACE, fg=MUTED,
                 wraplength=320, justify="left", font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))
        self.auth_title = tk.StringVar(value="Log in")
        self.auth_title_label = tk.Label(card, textvariable=self.auth_title, bg=SURFACE, fg=INK,
                                         font=("Segoe UI Semibold", 15))
        self.auth_title_label.pack(anchor="w", pady=(0, 12))
        tk.Label(card, text="Username", bg=SURFACE, fg=MUTED).pack(anchor="w")
        self.auth_username = tk.Entry(card, font=("Segoe UI", 11), relief="solid", bd=1)
        self.auth_username.pack(fill="x", ipady=7, pady=(4, 12))
        tk.Label(card, text="Password", bg=SURFACE, fg=MUTED).pack(anchor="w")
        self.auth_password = tk.Entry(card, font=("Segoe UI", 11), relief="solid", bd=1, show="•")
        self.auth_password.pack(fill="x", ipady=7, pady=(4, 14))
        self.auth_confirm_label = tk.Label(card, text="Confirm password", bg=SURFACE, fg=MUTED)
        self.auth_confirm_label.pack(anchor="w")
        self.auth_confirm_password = tk.Entry(card, font=("Segoe UI", 11), relief="solid", bd=1, show="•")
        self.auth_confirm_password.pack(fill="x", ipady=7, pady=(4, 12))
        self.auth_confirm_label.pack_forget()
        self.auth_confirm_password.pack_forget()
        self.auth_error = tk.StringVar(value="")
        self.auth_error_label = tk.Label(card, textvariable=self.auth_error, bg=SURFACE, fg=RED,
                         wraplength=340, justify="left")
        self.auth_error_label.pack(anchor="w", pady=(0, 6))
        self.auth_submit = tk.Button(card, text="Log in", command=self._submit_auth, bg=BLUE, fg="white",
                                     activebackground=BLUE_DARK, relief="flat", padx=12, pady=10,
                                     font=("Segoe UI Semibold", 10), cursor="hand2")
        self.auth_submit.pack(fill="x")
        self.auth_toggle = tk.Button(card, text="New here? Create an account", command=self._toggle_auth,
                                     bg=SURFACE, fg=BLUE, relief="flat", pady=10, cursor="hand2")
        self.auth_toggle.pack(anchor="center")
        tk.Label(card, text="Passwords are stored as salted PBKDF2 hashes.", bg=SURFACE, fg=MUTED,
                 font=("Segoe UI", 8)).pack(anchor="center", pady=(5, 0))
        self.auth_username.bind("<Return>", lambda _event: self.auth_password.focus_set())
        self.auth_password.bind("<Return>", self._submit_auth)
        self.auth_confirm_password.bind("<Return>", self._submit_auth)
        self.auth_mode = "login"

    def _show_auth(self):
        self.sidebar.pack_forget()
        self.main_area.pack_forget()
        self.auth_frame.pack(fill="both", expand=True)

    def _toggle_configure(self):
        if self.configure_frame.winfo_manager():
            self.configure_frame.pack_forget()
            self.configure_button.configure(text="Configure ▸")
        else:
            self.configure_frame.pack(fill="x", before=self.auth_title_label, pady=(0, 12))
            self.configure_button.configure(text="Configure ▾")

    def _toggle_auth(self):
        self.auth_mode = "register" if self.auth_mode == "login" else "login"
        registering = self.auth_mode == "register"
        self.auth_title.set("Create account" if registering else "Log in")
        self.auth_submit.configure(text="Create account" if registering else "Log in")
        self.auth_toggle.configure(text="Already registered? Log in" if registering else "New here? Create an account")
        if registering:
            self.auth_confirm_label.pack(before=self.auth_error_label, anchor="w")
            self.auth_confirm_password.pack(before=self.auth_error_label, fill="x", ipady=7, pady=(4, 12))
        else:
            self.auth_confirm_label.pack_forget()
            self.auth_confirm_password.pack_forget()
        self.auth_error.set("")

    def _submit_auth(self, _event=None):
        username, password = self.auth_username.get(), self.auth_password.get()
        registering = self.auth_mode == "register"
        if registering and password != self.auth_confirm_password.get():
            self.auth_error.set("Passwords do not match.")
            return
        try:
            database.configure_server_url(self.auth_server_var.get())
            self.auth_server_detail_var.set(f"Server: {database.SERVER_URL}")
        except (OSError, ValueError) as error:
            self.auth_error.set(str(error))
            return
        self.auth_submit.configure(state="disabled")

        def authenticate():
            if registering:
                return database.register_user(username, password)
            user = database.authenticate_user(username, password)
            if user is None:
                raise ValueError("Username or password is incorrect.")
            return user

        self._run_api_task(authenticate, self._complete_login, self._auth_failed)

    def _complete_login(self, user):
        self.auth_submit.configure(state="normal")
        self.user = user
        self.auth_frame.pack_forget()
        self.sidebar.pack(side="left", fill="y")
        self.main_area.pack(side="left", fill="both", expand=True)
        self.status_var.set(f"Signed in as {user['username']}.")
        self.refresh_history()
        self._load_latest_device_snapshot()

    def _load_latest_device_snapshot(self):
        def loaded(snapshot):
            self.latest_device_snapshot = snapshot
            for item in self.device_tree.get_children():
                self.device_tree.delete(item)
            if snapshot is None:
                self.device_status_var.set("No saved device discovery for this account.")
                return
            for device in snapshot.get("devices", []):
                self.device_tree.insert("", "end", values=(
                    device.get("ip", ""), device.get("mac", "Unknown"),
                    "Yes" if device.get("is_gateway") else "",
                    "Yes" if device.get("is_new") else "", "Yes" if device.get("is_local") else "",
                ))
            self.device_status_var.set(
                f"Last discovery: {snapshot.get('scanned_at', 'Unknown')} on {snapshot.get('subnet', 'Unknown')} "
                f"via gateway {snapshot.get('gateway_ip') or 'unknown'}."
            )

        self._run_api_task(database.latest_device_snapshot, loaded,
                           lambda error: self.device_status_var.set(f"Could not load device history: {error}"))

    def _auth_failed(self, error):
        self.auth_submit.configure(state="normal")
        self.auth_error.set(str(error))

    def logout(self):
        self.api_generation += 1
        database.logout()
        self.user = None
        self.latest_scan_id = None
        self.connection = None
        self.score_info = None
        self.viewing_saved_scan = False
        self.admin_password_var.set(False)
        self.password_var.set(False)
        self.ssid_var.set("No network scanned")
        for variable in self.metric_vars.values():
            variable.set("--")
        self.connection_badge.configure(text="●  Not scanned", bg=SURFACE_ALT, fg=MUTED)
        self.score_change_var.set("Your first scan sets a baseline")
        self._animate_score(0)
        self.auth_password.delete(0, "end")
        self.auth_username.delete(0, "end")
        self.auth_confirm_password.delete(0, "end")
        self.auth_confirm_label.pack_forget()
        self.auth_confirm_password.pack_forget()
        self.auth_mode = "login"
        self.auth_title.set("Log in")
        self.auth_submit.configure(text="Log in")
        self.auth_toggle.configure(text="New here? Create an account")
        self.auth_error.set("")
        self._show_auth()

    def start_performance_test(self):
        self._start_performance_test(include_speed_test=False)

    def start_speed_test(self):
        self._start_performance_test(include_speed_test=True)

    def _start_performance_test(self, include_speed_test):
        if self.connection is None:
            self.status_var.set("Scan the connected network before running performance tests.")
            return
        self.performance_button.configure(state="disabled", text="Testing...")
        self.speed_test_button.configure(state="disabled")
        test_label = "ping, DNS, and internet speed" if include_speed_test else "ping and DNS"
        self.performance_summary_var.set(f"Measuring {test_label}...")

        def measure():
            from performance_tests import measure_performance
            return measure_performance(include_speed_test=include_speed_test)

        def measured(metrics):
            self.performance_button.configure(state="normal", text="Quick test")
            self.speed_test_button.configure(state="normal")
            if self.connection is None:
                return
            previous_metrics = self.connection.get("performance_metrics") or {}
            if not include_speed_test and previous_metrics.get("speed"):
                metrics["speed"] = previous_metrics["speed"]
            self.connection["performance_metrics"] = metrics
            ping = metrics.get("ping") or {}
            dns = metrics.get("dns") or {}
            speed = metrics.get("speed") or {}
            from performance_tests import get_performance_recommendations
            recommendations = get_performance_recommendations(metrics, self.connection)
            self.connection["performance_recommendations"] = recommendations
            self.performance_summary_var.set(
                f"Ping: {ping.get('latency_ms', 'Unavailable')} ms | Loss: {ping.get('packet_loss_percent', 'Unavailable')}% | "
                f"DNS: {dns.get('resolution_ms', 'Unavailable')} ms | Download: {speed.get('download_mbps', 'Unavailable')} Mbps | "
                f"Upload: {speed.get('upload_mbps', 'Unavailable')} Mbps | {' '.join(recommendations)}"
            )
            self._render_backend_details(self.connection)
            self._save_assessment()
            self._update_report_summary()

        def failed(error):
            self.performance_button.configure(state="normal", text="Quick test")
            self.speed_test_button.configure(state="normal")
            self.performance_summary_var.set(str(error))

        self._run_api_task(measure, measured, failed)

    def start_device_discovery(self):
        self.device_scan_button.configure(state="disabled", text="Discovering...")
        self.device_status_var.set("Scanning the active IPv4 subnet. Administrator privileges may be required.")

        def discover():
            from device_discovery import discover_devices
            snapshot = discover_devices(interface_name=(self.connection or {}).get("interface"))
            return database.save_device_snapshot(snapshot, user_id=self.user["id"])

        def discovered(result):
            self.latest_device_snapshot = result
            self.device_scan_button.configure(state="normal", text="Discover devices")
            for item in self.device_tree.get_children():
                self.device_tree.delete(item)
            for device in result["devices"]:
                self.device_tree.insert("", "end", values=(
                    device["ip"], device["mac"], "Yes" if device.get("is_gateway") else "",
                    "Yes" if device.get("is_new") else "", "Yes" if device.get("is_local") else "",
                ))
            self.device_status_var.set(
                f"{len(result['devices'])} devices on {result['subnet']} via gateway "
                f"{result.get('gateway_ip') or 'unknown'} ({result['interface']})."
            )
            self._update_report_summary()

        def failed(error):
            self.device_scan_button.configure(state="normal", text="Discover devices")
            self.device_status_var.set(str(error))

        self._run_api_task(discover, discovered, failed)

    def _nav_button(self, key, icon, label):
        button = tk.Button(
            self.sidebar, text=f"  {icon}     {label}", command=lambda: self.show_page(key),
            anchor="w", relief="flat", bd=0, padx=15, pady=12, cursor="hand2",
            bg=NAVY, fg="#AFC0D6", activebackground=NAVY_2, activeforeground="white",
            font=("Segoe UI Semibold", 9),
        )
        button.pack(fill="x", padx=12, pady=2)
        self.nav_buttons[key] = button

    def show_page(self, page):
        self.current_page = page
        targets = {
            "dashboard": self.dashboard,
            "devices": self.devices,
            "history": self.history,
            "reports": self.reports,
            "account": self.account,
        }
        for frame in targets.values():
            frame.pack_forget()
        target = targets.get(page, self.dashboard)
        target.pack(fill="both", expand=True)
        self.breadcrumb_var.set(page.replace("_", " ").title())
        for key, button in self.nav_buttons.items():
            active = key == page
            button.configure(bg=NAVY_2 if active else NAVY, fg="white" if active else "#AFC0D6")

    def _card(self, parent, **kwargs):
        return tk.Frame(parent, bg=SURFACE, highlightbackground=LINE, highlightthickness=1, **kwargs)

    def _dashboard_mousewheel(self, event):
        if self.current_page == "dashboard" and self.dashboard_canvas.winfo_exists():
            self.dashboard_canvas.yview_scroll(int(-event.delta / 120), "units")

    @staticmethod
    def _scroll_nested_widget(event, widget):
        units = -1 if event.delta > 0 else 1
        widget.yview_scroll(units, "units")
        return "break"

    def _build_dashboard(self):
        viewport = tk.Frame(self.dashboard, bg=BG)
        viewport.pack(fill="both", expand=True)
        self.dashboard_canvas = tk.Canvas(viewport, bg=BG, highlightthickness=0)
        dashboard_scroll = ttk.Scrollbar(viewport, orient="vertical", command=self.dashboard_canvas.yview)
        self.dashboard_canvas.configure(yscrollcommand=dashboard_scroll.set)
        dashboard_scroll.pack(side="right", fill="y")
        self.dashboard_canvas.pack(side="left", fill="both", expand=True)
        page = tk.Frame(self.dashboard_canvas, bg=BG)
        page_window = self.dashboard_canvas.create_window((0, 0), window=page, anchor="nw")
        page.bind("<Configure>", lambda _event: self.dashboard_canvas.configure(
            scrollregion=self.dashboard_canvas.bbox("all")))
        self.dashboard_canvas.bind("<Configure>", lambda event: self.dashboard_canvas.itemconfigure(
            page_window, width=event.width))
        self.dashboard_canvas.bind_all("<MouseWheel>", self._dashboard_mousewheel)

        heading = tk.Frame(page, bg=BG)
        heading.pack(fill="x", pady=(0, 17))
        title_group = tk.Frame(heading, bg=BG)
        title_group.pack(side="left", fill="x", expand=True)
        tk.Label(title_group, text="Network overview", bg=BG, fg=INK,
                 font=("Segoe UI", 21, "bold")).pack(anchor="w")
        tk.Label(title_group, text="Your connection health and security status, in one place.",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 0))

        scan_actions = tk.Frame(heading, bg=BG)
        scan_actions.pack(side="right", padx=(12, 0), pady=(2, 0))
        self.scan_button = tk.Button(
            heading, text="  Scan network  ", command=self.start_scan,
            bg=BLUE, fg="white", activebackground=BLUE_DARK, activeforeground="white",
            relief="flat", bd=0, padx=13, pady=10, cursor="hand2",
            font=("Segoe UI Semibold", 9),
        )
        self.scan_button.pack(side="right", padx=(10, 0))
        tk.Checkbutton(scan_actions, text="Keep each scan", variable=self.separate_scan_history_var,
                   bg=BG, fg=INK, activebackground=BG, activeforeground=INK,
                   selectcolor=SURFACE, font=("Segoe UI", 8), cursor="hand2").pack(side="right")

        top_cards = tk.Frame(page, bg=BG)
        top_cards.pack(fill="x")
        score_card = self._card(top_cards, padx=19, pady=18, width=262, height=235)
        score_card.pack(side="left", fill="y", padx=(0, 13))
        score_card.pack_propagate(False)
        tk.Label(score_card, text="OVERALL WISE SCORE", bg=SURFACE, fg=MUTED,
                 font=("Segoe UI Semibold", 8)).pack(anchor="w")
        self.score_canvas = tk.Canvas(score_card, width=158, height=158, bg=SURFACE, highlightthickness=0)
        self.score_canvas.pack(pady=(5, 0))
        self._draw_score_ring(0)
        self.score_label_id = self.score_canvas.create_text(79, 71, text="--", fill=INK,
                                                           font=("Segoe UI", 28, "bold"))
        self.score_canvas.create_text(79, 101, text="out of 100", fill=MUTED,
                                      font=("Segoe UI", 8))
        self.score_change_var = tk.StringVar(value="Your first scan sets a baseline")
        tk.Label(score_card, textvariable=self.score_change_var, bg=SURFACE, fg=BLUE,
                 font=("Segoe UI Semibold", 8), wraplength=220).pack(anchor="center", pady=(1, 0))

        network_card = self._card(top_cards, padx=20, pady=18, height=235)
        network_card.pack(side="left", fill="both", expand=True)
        network_head = tk.Frame(network_card, bg=SURFACE)
        network_head.pack(fill="x")
        tk.Label(network_head, text="CONNECTED NETWORK", bg=SURFACE, fg=MUTED,
                 font=("Segoe UI Semibold", 8)).pack(side="left")
        self.network_status = tk.Label(network_head, text="Waiting for scan", bg=BLUE_PALE, fg=BLUE,
                                       padx=9, pady=4, font=("Segoe UI Semibold", 8))
        self.network_status.pack(side="right")
        self.ssid_var = tk.StringVar(value="No network scanned")
        tk.Label(network_card, textvariable=self.ssid_var, bg=SURFACE, fg=INK,
                 font=("Segoe UI", 18, "bold")).pack(anchor="w", pady=(17, 2))
        tk.Label(network_card, text="This is the Wi-Fi currently used by your computer.", bg=SURFACE,
                 fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w")
        tk.Frame(network_card, bg=LINE, height=1).pack(fill="x", pady=15)
        metrics = tk.Frame(network_card, bg=SURFACE)
        metrics.pack(fill="x")
        self.metric_vars = {key: tk.StringVar(value="--") for key in ("security", "signal", "cipher", "channel")}
        for index, (key, label) in enumerate((("security", "SECURITY"), ("signal", "SIGNAL"),
                                               ("cipher", "CIPHER"), ("channel", "CHANNEL"))):
            metric = tk.Frame(metrics, bg=SURFACE)
            metric.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 12, 0))
            metrics.grid_columnconfigure(index, weight=1)
            tk.Label(metric, text=label, bg=SURFACE, fg=MUTED,
                     font=("Segoe UI Semibold", 7)).pack(anchor="w")
            tk.Label(metric, textvariable=self.metric_vars[key], bg=SURFACE, fg=INK,
                     font=("Segoe UI Semibold", 9)).pack(anchor="w", pady=(4, 0))

        self.alert_card = tk.Frame(page, bg=SURFACE, padx=17, pady=14,
                                   highlightbackground=LINE, highlightthickness=1)
        self.alert_card.pack(fill="x", pady=13)
        alert_head = tk.Frame(self.alert_card, bg=SURFACE)
        alert_head.pack(fill="x")
        self.alert_icon = tk.Label(alert_head, text="i", bg=BLUE_PALE, fg=BLUE,
                                   width=2, pady=2, font=("Segoe UI", 10, "bold"))
        self.alert_icon.pack(side="left", padx=(0, 9))
        self.alert_title_var = tk.StringVar(value="Your security summary will appear here")
        tk.Label(alert_head, textvariable=self.alert_title_var, bg=SURFACE, fg=INK,
                 font=("Segoe UI Semibold", 10)).pack(side="left", anchor="w")
        self.alert_body_var = tk.StringVar(value="Scan the connected network for a clear explanation of its protection and any steps you can take.")
        tk.Label(self.alert_card, textvariable=self.alert_body_var, bg=SURFACE, fg=MUTED,
                 font=("Segoe UI", 9), wraplength=840, justify="left", anchor="w").pack(fill="x", padx=(37, 0), pady=(5, 0))

        performance_card = self._card(page, padx=18, pady=13)
        performance_card.pack(fill="x", pady=(0, 13))
        performance_header = tk.Frame(performance_card, bg=SURFACE)
        performance_header.pack(fill="x")
        tk.Label(performance_header, text="Performance tests", bg=SURFACE, fg=INK,
                 font=("Segoe UI Semibold", 11)).pack(side="left")
        performance_actions = tk.Frame(performance_header, bg=SURFACE)
        performance_actions.pack(side="right")
        self.performance_button = self._action_button(
            performance_actions, "Quick test", self.start_performance_test, BLUE_PALE, BLUE
        )
        self.performance_button.pack(side="left", padx=3)
        self.speed_test_button = self._action_button(
            performance_actions, "Speed test", self.start_speed_test, SURFACE_ALT, INK
        )
        self.speed_test_button.pack(side="left", padx=3)
        self.performance_summary_var = tk.StringVar(value="Optional active tests are not run during a routine Wi-Fi scan.")
        tk.Label(performance_card, textvariable=self.performance_summary_var, bg=SURFACE, fg=MUTED,
                 wraplength=880, justify="left", font=("Segoe UI", 9)).pack(anchor="w", pady=(8, 0))

        self.details_panel = self._card(page, padx=18, pady=15)
        self.details_panel.pack(fill="x", pady=(0, 13))
        details_heading = tk.Frame(self.details_panel, bg=SURFACE)
        details_heading.pack(fill="x", pady=(0, 10))
        tk.Label(details_heading, text="Connection details", bg=SURFACE, fg=INK,
                 font=("Segoe UI Semibold", 11)).pack(side="left")
        tk.Label(details_heading, textvariable=self.details_source_var, bg=SURFACE, fg=BLUE,
                 font=("Segoe UI Semibold", 7)).pack(side="right")
        self.details_grid = tk.Frame(self.details_panel, bg=SURFACE)
        self.details_grid.pack(fill="x")
        for column in range(3):
            self.details_grid.grid_columnconfigure(column, weight=1, uniform="details")

        environment_card = self._card(page, padx=18, pady=15)
        environment_card.pack(fill="x", pady=(0, 13))
        env_heading = tk.Frame(environment_card, bg=SURFACE)
        env_heading.pack(fill="x")
        tk.Label(env_heading, text="Wi-Fi environment & channel recommendation", bg=SURFACE, fg=INK,
                 font=("Segoe UI Semibold", 11)).pack(side="left")
        self.congestion_badge = tk.Label(env_heading, text="Not analyzed", bg=BLUE_PALE, fg=BLUE,
                                         padx=9, pady=4, font=("Segoe UI Semibold", 8))
        self.congestion_badge.pack(side="right")
        self.environment_var = tk.StringVar(value="Run a scan to analyze nearby networks and channel congestion.")
        tk.Label(environment_card, textvariable=self.environment_var, bg=SURFACE, fg=MUTED,
                 wraplength=900, justify="left", font=("Segoe UI", 9)).pack(anchor="w", pady=(9, 8))
        self.channel_scores_frame = tk.Frame(environment_card, bg=SURFACE)
        self.channel_scores_frame.pack(fill="x")

        recommendations_card = self._card(page, padx=18, pady=15)
        recommendations_card.pack(fill="x", pady=(0, 13))
        tk.Label(recommendations_card, text="Recommendations from your analysis", bg=SURFACE, fg=INK,
                 font=("Segoe UI Semibold", 11)).pack(anchor="w", pady=(0, 9))
        self.recommendations_frame = tk.Frame(recommendations_card, bg=SURFACE)
        self.recommendations_frame.pack(fill="x")

        nearby_card = self._card(page, padx=16, pady=14)
        nearby_card.pack(fill="x", pady=(0, 13))
        nearby_head = tk.Frame(nearby_card, bg=SURFACE)
        nearby_head.pack(fill="x", pady=(0, 9))
        tk.Label(nearby_head, text="Nearby networks", bg=SURFACE, fg=INK,
                 font=("Segoe UI Semibold", 11)).pack(side="left")
        tk.Label(nearby_head, text="SELECT A ROW FOR FULL ANALYSIS", bg=SURFACE, fg=MUTED,
                 font=("Segoe UI Semibold", 7)).pack(side="right")
        nearby_table = tk.Frame(nearby_card, bg=SURFACE)
        nearby_table.pack(fill="x")
        nearby_columns = ("ssid", "bssid", "quality", "security", "band", "channel", "channel_status", "risk")
        self.nearby_tree = ttk.Treeview(nearby_table, columns=nearby_columns, show="headings", height=5,
                                        selectmode="browse", style="Wise.Treeview")
        for column, label, width in (("ssid", "SSID", 150), ("bssid", "BSSID", 145),
                                      ("quality", "QUALITY", 82), ("security", "SECURITY", 105),
                                      ("band", "BAND", 85), ("channel", "CHANNEL", 80),
                                      ("channel_status", "CHANNEL STATUS", 130), ("risk", "IDENTITY RISK", 145)):
            self.nearby_tree.heading(column, text=label)
            self.nearby_tree.column(column, width=width, anchor="w" if column in ("ssid", "bssid") else "center")
        self.nearby_tree.pack(side="left", fill="x", expand=True)
        nearby_tree_scroll = ttk.Scrollbar(nearby_table, orient="vertical", command=self.nearby_tree.yview)
        self.nearby_tree.configure(yscrollcommand=nearby_tree_scroll.set)
        nearby_tree_scroll.pack(side="right", fill="y")
        self.nearby_tree.bind("<<TreeviewSelect>>", self._show_nearby_details)
        self.nearby_tree.bind(
            "<MouseWheel>", lambda event: self._scroll_nested_widget(event, self.nearby_tree)
        )
        nearby_details_frame = tk.Frame(nearby_card, bg=SURFACE)
        nearby_details_frame.pack(fill="x", pady=(9, 0))
        self.nearby_details = tk.Text(nearby_details_frame, height=11, wrap="word", bg=SURFACE_ALT,
                                      fg=INK, relief="flat", padx=10, pady=8,
                                      font=("Consolas", 8), state="disabled")
        self.nearby_details.pack(side="left", fill="x", expand=True)
        nearby_details_scroll = ttk.Scrollbar(nearby_details_frame, orient="vertical",
                                              command=self.nearby_details.yview)
        self.nearby_details.configure(yscrollcommand=nearby_details_scroll.set)
        nearby_details_scroll.pack(side="right", fill="y")
        self.nearby_details.bind(
            "<MouseWheel>", lambda event: self._scroll_nested_widget(event, self.nearby_details)
        )

        bottom = tk.Frame(page, bg=BG)
        bottom.pack(fill="both", expand=True, pady=(0, 12))
        breakdown = self._card(bottom, padx=18, pady=15)
        breakdown.pack(side="left", fill="both", expand=True, padx=(0, 13))
        bhead = tk.Frame(breakdown, bg=SURFACE)
        bhead.pack(fill="x", pady=(0, 11))
        tk.Label(bhead, text="Score breakdown", bg=SURFACE, fg=INK,
                 font=("Segoe UI Semibold", 11)).pack(side="left")
        tk.Label(bhead, text="100 POINTS", bg=BLUE_PALE, fg=BLUE,
                 padx=8, pady=4, font=("Segoe UI Semibold", 7)).pack(side="right")
        for key, label, possible in (("security", "Security", 50),
                         ("performance", "Performance", 30),
                         ("configuration", "Configuration", 20)):
            row = tk.Frame(breakdown, bg=SURFACE)
            row.pack(fill="x", pady=6)
            row_header = tk.Frame(row, bg=SURFACE)
            row_header.pack(fill="x")
            tk.Label(row_header, text=label, bg=SURFACE, fg=INK,
                     font=("Segoe UI Semibold", 8)).pack(side="left")
            value_var = tk.StringVar(value=f"0 / {possible}")
            tk.Label(row_header, textvariable=value_var, bg=SURFACE, fg=MUTED,
                     font=("Segoe UI Semibold", 8)).pack(side="right")
            bar = ttk.Progressbar(row, style="Wise.Horizontal.TProgressbar", maximum=possible,
                                  mode="determinate", value=0)
            bar.pack(fill="x", pady=(6, 3))
            note_var = tk.StringVar(value="Run a scan to calculate")
            tk.Label(row, textvariable=note_var, bg=SURFACE, fg=MUTED,
                     font=("Segoe UI", 7)).pack(anchor="w")
            self.score_rows[key] = (value_var, bar, note_var)

        ownership = self._card(bottom, padx=17, pady=15, width=300)
        ownership.pack(side="right", fill="y")
        ownership.pack_propagate(False)
        tk.Label(ownership, text="About your network", bg=SURFACE, fg=INK,
                 font=("Segoe UI Semibold", 11)).pack(anchor="w")
        tk.Label(ownership, text="Your confirmations contribute to configuration. WISE cannot inspect your passwords.",
                 bg=SURFACE, fg=MUTED, wraplength=260, justify="left",
                 font=("Segoe UI", 8)).pack(anchor="w", pady=(6, 11))
        self.admin_password_check = self._themed_check(
            ownership, "I changed the router's default admin password", self.admin_password_var
        )
        self.admin_password_check.pack(anchor="w", fill="x", pady=4)
        self.password_check = self._themed_check(ownership, "I use a strong, unique Wi-Fi password", self.password_var)
        self.password_check.pack(anchor="w", fill="x", pady=4)
        tk.Label(ownership, text="Tip: a long passphrase is easier to remember and harder to guess.",
                 bg=BLUE_PALE, fg=NAVY_2, padx=10, pady=9, wraplength=250,
                 justify="left", font=("Segoe UI", 8)).pack(fill="x", pady=(12, 0))

    def _themed_check(self, parent, text, variable):
        return tk.Checkbutton(
            parent, text=text, variable=variable, command=self._recalculate_current,
            bg=SURFACE, fg=INK, activebackground=SURFACE, activeforeground=INK,
            selectcolor=SURFACE, wraplength=255, justify="left", anchor="w",
            font=("Segoe UI", 8), padx=0, pady=3, cursor="hand2",
        )

    def _build_history(self):
        heading = tk.Frame(self.history, bg=BG)
        heading.pack(fill="x", pady=(0, 16))
        title_group = tk.Frame(heading, bg=BG)
        title_group.pack(side="left", fill="x", expand=True)
        tk.Label(title_group, text="Scan history", bg=BG, fg=INK,
                 font=("Segoe UI", 21, "bold")).pack(anchor="w")
        tk.Label(title_group, text="Review how your Wi-Fi security score changes over time.",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 0))
        actions = tk.Frame(heading, bg=BG)
        actions.pack(side="right")
        self._action_button(actions, "Refresh", self.refresh_history, BLUE_PALE, BLUE).pack(side="left", padx=4)
        self._action_button(actions, "Compare two", self.compare_selected_scans, BLUE_PALE, BLUE).pack(side="left", padx=4)
        self._action_button(actions, "Export CSV", self.export_history_csv, SURFACE_ALT, INK).pack(side="left", padx=4)
        self._action_button(actions, "Delete selected", self.delete_selected_scan, RED_PALE, RED).pack(side="left", padx=4)
        self._action_button(actions, "Clear history", self.delete_all_history, SURFACE, MUTED).pack(side="left", padx=4)

        filter_bar = tk.Frame(self.history, bg=BG)
        filter_bar.pack(fill="x", pady=(0, 10))
        tk.Label(filter_bar, text="Filter SSID", bg=BG, fg=MUTED,
             font=("Segoe UI Semibold", 8)).pack(side="left", padx=(0, 8))
        self.history_filter_var = tk.StringVar(value="")
        filter_entry = tk.Entry(filter_bar, textvariable=self.history_filter_var,
                    font=("Segoe UI", 9), relief="solid", bd=1)
        filter_entry.pack(side="left", fill="x", expand=True)
        self.history_filter_var.trace_add("write", lambda *_args: self._render_history_rows())

        summary = self._card(self.history, padx=17, pady=14)
        summary.pack(fill="x", pady=(0, 13))
        self.history_summary_var = tk.StringVar(value="No saved scans yet")
        tk.Label(summary, textvariable=self.history_summary_var, bg=SURFACE, fg=INK,
                 font=("Segoe UI Semibold", 9)).pack(anchor="w")
        panel = self._card(self.history, padx=10, pady=10)
        panel.pack(fill="both", expand=True)
        columns = ("date", "ssid", "score", "protocol", "company", "other")
        self.history_tree = ttk.Treeview(panel, columns=columns, show="headings",
                         selectmode="extended", style="Wise.Treeview")
        headers = (("date", "DATE / TIME", 190), ("ssid", "NETWORK", 190),
               ("score", "SCORE", 115), ("protocol", "SECURITY", 115),
               ("company", "CONFIGURATION", 150), ("other", "PERFORMANCE", 120))
        for column, label, width in headers:
            self.history_tree.heading(column, text=label)
            self.history_tree.column(column, width=width, anchor="w" if column in ("date", "ssid") else "center")
        self.history_tree.pack(fill="both", expand=True)
        self.history_tree.bind("<Double-1>", self.open_saved_scan)
        tk.Label(panel, text="Double-click a scan to open its details on the overview page.",
                 bg=SURFACE, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w", pady=(9, 2))
        self.trend_frame = self._card(self.history, padx=12, pady=10)
        self.trend_frame.pack(fill="x", pady=(0, 13))
        tk.Label(self.trend_frame, text="Score trends", bg=SURFACE, fg=INK,
                 font=("Segoe UI Semibold", 10)).pack(anchor="w", pady=(0, 6))
        self.trend_plot = tk.Frame(self.trend_frame, bg=SURFACE)
        self.trend_plot.pack(fill="x")

    def _build_devices(self):
        heading = tk.Frame(self.devices, bg=BG)
        heading.pack(fill="x", pady=(0, 16))
        tk.Label(heading, text="Device discovery", bg=BG, fg=INK,
                 font=("Segoe UI", 21, "bold")).pack(side="left")
        self.device_scan_button = self._action_button(
            heading, "Discover devices", self.start_device_discovery, BLUE_PALE, BLUE
        )
        self.device_scan_button.pack(side="right")
        panel = self._card(self.devices, padx=14, pady=12)
        panel.pack(fill="both", expand=True)
        self.device_status_var = tk.StringVar(value="No device discovery run yet.")
        tk.Label(panel, textvariable=self.device_status_var, bg=SURFACE, fg=MUTED,
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 10))
        columns = ("ip", "mac", "gateway", "new", "local")
        self.device_tree = ttk.Treeview(panel, columns=columns, show="headings", style="Wise.Treeview", height=14)
        for column, label, width in (("ip", "IP ADDRESS", 190), ("mac", "MAC ADDRESS", 210),
                         ("gateway", "GATEWAY", 100), ("new", "NEW", 80),
                         ("local", "THIS DEVICE", 110)):
            self.device_tree.heading(column, text=label)
            self.device_tree.column(column, width=width, anchor="center")
        self.device_tree.pack(fill="both", expand=True)

    def _build_reports(self):
        heading = tk.Frame(self.reports, bg=BG)
        heading.pack(fill="x", pady=(0, 16))
        tk.Label(heading, text="Assessment report", bg=BG, fg=INK,
                 font=("Segoe UI", 21, "bold")).pack(side="left")
        self.report_export_button = self._action_button(
            heading, "Export PDF", self.export_report, BLUE_PALE, BLUE
        )
        self.report_export_button.pack(side="right")
        panel = self._card(self.reports, padx=18, pady=16)
        panel.pack(fill="x")
        self.report_summary_var = tk.StringVar(value="Run a Wi-Fi scan to prepare an assessment report.")
        tk.Label(panel, textvariable=self.report_summary_var, bg=SURFACE, fg=INK,
                 wraplength=900, justify="left", font=("Segoe UI", 10)).pack(anchor="w")
        self.report_details_var = tk.StringVar(value="")
        tk.Label(panel, textvariable=self.report_details_var, bg=SURFACE, fg=MUTED,
                 wraplength=900, justify="left", font=("Segoe UI", 9)).pack(anchor="w", pady=(8, 0))

    def _build_account_settings(self):
        heading = tk.Frame(self.account, bg=BG)
        heading.pack(fill="x", pady=(0, 16))
        tk.Label(heading, text="Account settings", bg=BG, fg=INK,
                 font=("Segoe UI", 21, "bold")).pack(anchor="w")
        panel = self._card(self.account, padx=18, pady=16)
        panel.pack(fill="x")
        tk.Label(panel, text="Change password", bg=SURFACE, fg=INK,
                 font=("Segoe UI Semibold", 12)).pack(anchor="w", pady=(0, 10))
        for label, attribute in (("Current password", "current_password_entry"),
                                 ("New password", "new_password_entry"),
                                 ("Confirm new password", "confirm_new_password_entry")):
            tk.Label(panel, text=label, bg=SURFACE, fg=MUTED,
                     font=("Segoe UI", 9)).pack(anchor="w", pady=(5, 0))
            entry = tk.Entry(panel, show="•", font=("Segoe UI", 10), relief="solid", bd=1)
            entry.pack(fill="x", ipady=6, pady=(3, 4))
            setattr(self, attribute, entry)
        self.account_status_var = tk.StringVar(value="")
        tk.Label(panel, textvariable=self.account_status_var, bg=SURFACE, fg=RED,
                 wraplength=850, justify="left").pack(anchor="w", pady=(4, 8))
        self._action_button(panel, "Change password", self.change_account_password, BLUE_PALE, BLUE).pack(anchor="w")
        tk.Frame(panel, bg=LINE, height=1).pack(fill="x", pady=16)
        tk.Label(panel, text="Delete account", bg=SURFACE, fg=RED,
                 font=("Segoe UI Semibold", 12)).pack(anchor="w")
        tk.Label(panel, text="Permanently deletes this account and all associated scans and device history.",
                 bg=SURFACE, fg=MUTED, wraplength=850, justify="left",
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(5, 9))
        tk.Label(panel, text="Current password", bg=SURFACE, fg=MUTED,
             font=("Segoe UI", 9)).pack(anchor="w")
        self.delete_account_password = tk.Entry(panel, show="•", font=("Segoe UI", 10), relief="solid", bd=1)
        self.delete_account_password.pack(fill="x", ipady=6, pady=(3, 8))
        self._action_button(panel, "Delete account...", self.delete_account, RED_PALE, RED).pack(anchor="w")

    def change_account_password(self):
        current_password = self.current_password_entry.get()
        new_password = self.new_password_entry.get()
        if len(new_password) < 8:
            self.account_status_var.set("New password must be at least 8 characters long.")
            return
        if new_password != self.confirm_new_password_entry.get():
            self.account_status_var.set("New passwords do not match.")
            return
        self._run_api_task(
            lambda: database.change_password(current_password, new_password),
            lambda _result: self._password_changed(),
            lambda error: self.account_status_var.set(str(error)),
        )

    def _password_changed(self):
        for entry in (self.current_password_entry, self.new_password_entry, self.confirm_new_password_entry):
            entry.delete(0, "end")
        self.account_status_var.set("Password changed. Other signed-in sessions were revoked.")

    def delete_account(self):
        password = self.delete_account_password.get()
        if not password:
            self.account_status_var.set("Enter your current password to confirm account deletion.")
            return
        if not messagebox.askyesno(
            "Delete account permanently",
            "Delete this account and all associated scans and device history? This cannot be undone.",
        ):
            return

        def deleted(_result):
            self.logout()
            self.status_var.set("Account and associated history deleted.")

        self._run_api_task(lambda: database.delete_account(password), deleted,
                           lambda error: self.account_status_var.set(str(error)))

    def _render_trend_chart(self, rows):
        for child in self.trend_plot.winfo_children():
            child.destroy()
        if not rows:
            tk.Label(self.trend_plot, text="Saved scores will appear here after your first assessment.",
                     bg=SURFACE, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w")
            return
        try:
            import matplotlib.dates as mdates
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            from matplotlib.figure import Figure
        except ImportError:
            tk.Label(self.trend_plot, text="Install matplotlib to display score trends.",
                     bg=SURFACE, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w")
            return

        grouped_rows = {}
        for row in sorted(rows, key=lambda item: (item["scanned_at"], item["id"])):
            ssid = str(row.get("ssid") or "<Hidden>")
            grouped_rows.setdefault(ssid, []).append(row)
        figure = Figure(figsize=(8.4, 2.3), dpi=90, facecolor=SURFACE)
        axis = figure.add_subplot(111)
        for ssid, network_rows in grouped_rows.items():
            dates = [datetime.fromisoformat(row["scanned_at"]) for row in network_rows]
            scores = [row["score"] for row in network_rows]
            axis.plot(dates, scores, linewidth=2, marker="o", markersize=4, label=ssid)
        if len(grouped_rows) > 1:
            axis.legend(loc="best", fontsize=7)
        axis.set_ylim(0, 100)
        axis.set_ylabel("Score")
        axis.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))
        axis.grid(axis="y", color=LINE, linewidth=0.7)
        axis.spines["top"].set_visible(False)
        axis.spines["right"].set_visible(False)
        figure.tight_layout()
        self._trend_figure = figure
        self._trend_canvas = FigureCanvasTkAgg(figure, master=self.trend_plot)
        self._trend_canvas.draw()
        self._trend_canvas.get_tk_widget().pack(fill="x")

    @staticmethod
    def _format_performance(metrics):
        if not metrics:
            return "Performance tests have not been run."
        ping = metrics.get("ping") or {}
        dns = metrics.get("dns") or {}
        speed = metrics.get("speed") or {}
        return (
            f"Ping: {ping.get('latency_ms', 'Unavailable')} ms; loss: {ping.get('packet_loss_percent', 'Unavailable')}%; "
            f"DNS: {dns.get('resolution_ms', 'Unavailable')} ms; download: {speed.get('download_mbps', 'Unavailable')} Mbps; "
            f"upload: {speed.get('upload_mbps', 'Unavailable')} Mbps"
        )

    def export_report(self):
        if self.connection is None or self.score_info is None:
            messagebox.showinfo("No assessment", "Run or open a scan before exporting a report.")
            return
        path = filedialog.asksaveasfilename(
            title="Export WISE assessment",
            defaultextension=".pdf",
            filetypes=(("PDF report", "*.pdf"),),
            initialfile="wise-assessment.pdf",
        )
        if not path:
            return
        connection = dict(self.connection)
        score_info = dict(self.score_info)
        nearby_networks = list(connection.get("nearby_networks", []))
        score_change = self.score_change_var.get()
        device_snapshot = self.latest_device_snapshot

        def write_report():
            from reporting import export_pdf
            return export_pdf(path, connection, score_info, nearby_networks,
                              score_change=score_change, device_snapshot=device_snapshot)

        self._run_api_task(
            write_report,
            lambda saved_path: self.status_var.set(f"PDF report saved to {saved_path}."),
            lambda error: messagebox.showerror("Report export failed", str(error)),
        )

    def _action_button(self, parent, text, command, background, foreground):
        return tk.Button(parent, text=text, command=command, bg=background, fg=foreground,
                         activebackground=background, activeforeground=foreground,
                         relief="flat", bd=0, padx=11, pady=8, cursor="hand2",
                         font=("Segoe UI Semibold", 8))

    def _draw_score_ring(self, score):
        canvas = self.score_canvas
        canvas.delete("ring-track")
        canvas.delete("ring-value")
        canvas.create_oval(14, 6, 144, 136, outline="#E9EEF5", width=11, tags="ring-track")
        if score > 0:
            color = GREEN if score >= 75 else AMBER if score >= 45 else RED
            extent = -359.9 * min(max(score, 0), 100) / 100
            canvas.create_arc(14, 6, 144, 136, start=90, extent=extent,
                              style="arc", outline=color, width=11, tags="ring-value")

    def _animate_score(self, target):
        if self.score_animation_id:
            self.after_cancel(self.score_animation_id)
            self.score_animation_id = None
        start = self.score_ring_value
        steps = 22
        def tick(step=0):
            value = round(start + (target - start) * min(step / steps, 1))
            self._draw_score_ring(value)
            self.score_canvas.itemconfigure(self.score_label_id, text=str(value))
            self.score_ring_value = value
            if step < steps:
                self.score_animation_id = self.after(16, lambda: tick(step + 1))
            else:
                self.score_animation_id = None
        tick()

    def _animate_bars(self, score_info):
        for callback_id in self.bar_animation_ids:
            try:
                self.after_cancel(callback_id)
            except tk.TclError:
                pass
        self.bar_animation_ids.clear()
        targets = {}
        for item in score_info["breakdown"]:
            key = {
                "Security": "security", "Performance": "performance", "Configuration": "configuration",
                "Security protocol": "security", "Company SSID/password": "configuration",
                "Other safeguards": "performance",
            }.get(item["category"])
            if key in self.score_rows:
                value_var, bar, note_var = self.score_rows[key]
                maximum = int(float(bar["maximum"]))
                earned = min(int(item["earned"]), maximum)
                value_var.set(f"{earned} / {maximum}")
                note_var.set(item["note"])
                targets[key] = (bar, earned, int(bar["value"]))
        for frame in range(1, 15):
            def draw(frame=frame):
                for bar, target, start in targets.values():
                    bar["value"] = round(start + (target - start) * frame / 14)
            self.bar_animation_ids.append(self.after(18 * frame, draw))

    def _close_app(self):
        self.closing = True
        self.scan_session += 1
        for callback_id in (self.scan_poll_id, self.scan_animation_id, self.score_animation_id,
                            *self.bar_animation_ids):
            if callback_id:
                try:
                    self.after_cancel(callback_id)
                except tk.TclError:
                    pass
        self.destroy()

    def _process_scan_events(self):
        self.scan_poll_id = None
        try:
            event = self.scan_events.get_nowait()
        except queue.Empty:
            event = None

        if event is not None:
            kind, session, *payload = event
            if kind == "api":
                generation, on_success, on_error, result, error = payload
                if generation == self.api_generation:
                    if isinstance(error, database.SessionExpired):
                        self._session_expired()
                    elif error is not None:
                        on_error(error)
                    else:
                        on_success(result)
            elif session == self.scan_session:
                if kind == "connection":
                    self._on_connection_read(session, payload[0])
                elif kind == "analysis":
                    connection, networks, environment, error = payload
                    self._apply_analysis(session, connection, networks, environment, error)
                elif kind == "failure":
                    self._scan_failed(payload[0])

        if not self.closing:
            self.scan_poll_id = self.after(60, self._process_scan_events)

    def _run_api_task(self, operation, on_success, on_error=None):
        generation = self.api_generation
        on_error = on_error or (lambda error: self.status_var.set(f"Server request failed: {error}"))

        def worker():
            try:
                result = operation()
                error = None
            except Exception as caught:
                result = None
                error = caught
            self.scan_events.put(("api", None, generation, on_success, on_error, result, error))

        threading.Thread(target=worker, daemon=True).start()

    def _session_expired(self):
        self.logout()
        self.auth_error.set("Your session expired. Please log in again.")
        self.status_var.set("Session expired. Sign in again to continue.")

    def start_scan(self):
        self.scan_session += 1
        session = self.scan_session
        if self.scan_animation_id:
            self.after_cancel(self.scan_animation_id)
        self.scan_button.configure(state="disabled")
        self.network_status.configure(text="Scanning...", bg=BLUE_PALE, fg=BLUE)
        self.status_var.set("Checking your active connection...")
        self._scan_pulse(0)
        threading.Thread(target=self._scan_worker, args=(session,), daemon=True).start()

    def _scan_pulse(self, frame):
        if self.scan_button["state"] == "disabled":
            label = "Scanning" + "." * (frame % 4)
            self.scan_button.configure(text=f"  {label:<12}")
            self.scan_animation_id = self.after(260, lambda: self._scan_pulse(frame + 1))
        else:
            self.scan_animation_id = None

    def _scan_worker(self, session):
        try:
            from conn_network import connected_wifi
            connection = connected_wifi()
        except Exception as error:
            self.scan_events.put(("failure", session, str(error)))
            return
        self.scan_events.put(("connection", session, connection))

        # Scan the Windows WLAN interface after saving the connected-network score.
        try:
            from analyzer import analyze
            networks, environment = analyze(connection)
            self.scan_events.put(("analysis", session, connection, networks, environment, None))
        except Exception as analysis_error:
            self.scan_events.put(("analysis", session, connection, [], None, str(analysis_error)))

    def _on_connection_read(self, session, connection):
        if session != self.scan_session:
            return
        self._show_connection(connection)

    def _apply_analysis(self, session, original_connection, networks, environment, error):
        if session != self.scan_session or not self.connection:
            return
        if self.connection.get("ssid", "").strip().casefold() != original_connection.get("ssid", "").strip().casefold():
            return
        connection = dict(original_connection)
        if error:
            connection["analysis_error"] = error
        else:
            active_bssid = str(connection.get("bssid", "")).strip().casefold()
            active_ssid = connection.get("ssid", "").strip().casefold()
            matches = ([network for network in networks
                        if str(network.get("bssid", "")).strip().casefold() == active_bssid]
                       if active_bssid else [])
            if not matches:
                matches = [network for network in networks
                           if str(network.get("ssid", "")).strip().casefold() == active_ssid]
            if matches:
                connection["analysis"] = max(matches, key=lambda network: network.get("quality", 0))
                connection["ssid_hygiene"] = connection["analysis"].get("ssid_hygiene", {})
                connection["rogue_ap_suspected"] = connection["analysis"].get("rogue_ap_suspected", False)
                if connection.get("rssi") is None:
                    connection["rssi"] = connection["analysis"].get("signal")
            connection["nearby_networks"] = networks
            connection["environment"] = environment
        if not connection.get("channel_status"):
            connection["channel_status"] = self._connected_channel_status(connection)
        connection.setdefault("channel_advice", self._connected_channel_advice(connection))
        from performance_tests import get_performance_recommendations
        performance_metrics = connection.get("performance_metrics") or {}
        connection["performance_recommendations"] = get_performance_recommendations(
            performance_metrics, connection
        )
        active_ssid = str(connection.get("ssid", "")).strip().casefold()
        connection["rogue_ap_suspected"] = any(
            str(network.get("ssid", "")).strip().casefold() == active_ssid
            and network.get("rogue_ap_suspected", False)
            for network in networks
        )
        self.connection.update(connection)
        self.score_info = score_connection(
            self.connection,
            password_policy_ok=self.password_var.get(),
            router_admin_password_ok=self.admin_password_var.get(),
        )
        self._animate_score(self.score_info["total"])
        self._animate_bars(self.score_info)
        self._render_security_alert(self.connection)
        self._render_backend_details(self.connection)
        self._update_report_summary()
        # Persist the analyzer payload into the existing scan record.
        if self.latest_scan_id is not None and self.score_info is not None:
            connection_snapshot = dict(self.connection)
            score_snapshot = dict(self.score_info)
            update_id = self.latest_scan_id
            user_id = self.user["id"]
            self._run_api_task(
                lambda: database.save_scan(connection_snapshot, score_snapshot,
                                           update_id=update_id, user_id=user_id),
                lambda _saved: None,
                lambda save_error: self.status_var.set(
                    f"Score saved, but detailed scan data could not be stored: {save_error}"
                ),
            )
        if error:
            self.status_var.set(f"Connected Wi-Fi score saved. Nearby analysis unavailable: {error}")
        elif networks:
            self.status_var.set(f"Connected Wi-Fi score saved. Nearby analysis updated: {len(networks)} networks found.")
        else:
            self.status_var.set(
                "Connected Wi-Fi score saved. No nearby networks were returned; check the wireless adapter and scan again."
            )

    def _scan_failed(self, error):
        self.scan_button.configure(state="normal", text="  Scan network  ")
        self.network_status.configure(text="Scan unavailable", bg=AMBER_PALE, fg=AMBER)
        self.status_var.set("Could not read the current Wi-Fi connection.")
        messagebox.showerror("Wi-Fi scan failed", error)

    @staticmethod
    def _connected_channel_status(connection):
        channel = connection.get("channel")
        if not isinstance(channel, int):
            return "Unknown"
        if 1 <= channel <= 14:
            band = "2.4 GHz"
        elif 36 <= channel <= 177:
            band = "5 GHz"
        elif 178 <= channel <= 233:
            band = "6 GHz"
        else:
            return "Unknown"
        return get_channel_status(band, channel)

    @classmethod
    def _connected_channel_advice(cls, connection):
        status = cls._connected_channel_status(connection)
        if status == "Overlapping":
            return ["This channel overlaps with nearby channels; consider a non-overlapping channel if interference is present."]
        if status in ("Recommended", "Good", "Excellent"):
            return ["The reported channel is in a generally suitable range for its band."]
        return ["Channel advice is unavailable because Windows did not report a recognized channel."]

    def _show_connection(self, connection):
        previous_connection = self.connection
        same_network = (
            previous_connection is not None
            and str(previous_connection.get("ssid", "")).strip().casefold()
            == str(connection.get("ssid", "")).strip().casefold()
        )
        previous_password_ok = self.password_var.get() if same_network else False
        previous_admin_password_ok = self.admin_password_var.get() if same_network else False
        self.connection = connection
        self.viewing_saved_scan = False
        self.latest_scan_id = None
        self.scan_button.configure(state="normal", text="  Scan network  ")
        self.admin_password_var.set(previous_admin_password_ok)
        self.password_var.set(previous_password_ok)
        self.performance_summary_var.set("Optional active tests are not run during a routine Wi-Fi scan.")
        ssid = connection.get("ssid", "Unknown network")
        auth = connection.get("authentication", "Unknown")
        signal = connection.get("signal_percent")
        channel = connection.get("channel")
        self.ssid_var.set(ssid)
        self.metric_vars["security"].set(auth)
        self.metric_vars["signal"].set(f"{signal}%" if signal is not None else "Unknown")
        self.metric_vars["cipher"].set(connection.get("cipher", "Unknown"))
        self.metric_vars["channel"].set(str(channel) if channel is not None else "Unknown")
        self.connection_badge.configure(text="●  Connected", bg=GREEN_PALE, fg=GREEN)
        self.network_status.configure(text="Active connection", bg=GREEN_PALE, fg=GREEN)
        self._render_security_alert(connection)
        self._render_backend_details(connection)
        self._update_report_summary()
        if same_network:
            self._save_assessment()
        elif self.user is not None:
            connection_ref = self.connection
            user_id = self.user["id"]
            ssid_key = str(connection.get("ssid", "")).strip().casefold()

            def load_previous_preferences():
                rows = database.list_scans(user_id)
                previous = next((row for row in rows
                                 if str(row.get("ssid", "")).strip().casefold() == ssid_key), None)
                return database.get_scan(previous["id"], user_id) if previous else None

            def restore_preferences(record):
                if self.connection is not connection_ref:
                    return
                if record is not None:
                    saved_score = record.get("score_details", {})
                    self.password_var.set(saved_score.get("password_policy_ok", False))
                    self.admin_password_var.set(saved_score.get("router_admin_password_ok", False))
                self._save_assessment()

            self._run_api_task(load_previous_preferences, restore_preferences)

    def _render_backend_details(self, connection):
        analysis = connection.get("analysis") or {}
        self.details_source_var.set(
            "SAVED ASSESSMENT" if self.viewing_saved_scan else "CURRENT INTERFACE + ANALYZER"
        )

        detail_items = [
            ("Connected interface", connection.get("interface")),
            ("Connection status", connection.get("state")),
            ("SSID", connection.get("ssid")),
            ("Saved profile", connection.get("profile")),
            ("Authentication", connection.get("authentication")),
            ("Cipher", connection.get("cipher")),
            ("Signal", f"{connection.get('signal_percent')}%" if connection.get("signal_percent") is not None else None),
            ("RSSI", f"{connection.get('rssi')} dBm" if connection.get("rssi") is not None else None),
            ("Channel", connection.get("channel")),
            ("Channel status", connection.get("channel_status") or analysis.get("channel_status")),
            ("Possible rogue AP", connection.get("rogue_ap_suspected")),
            ("Radio type", connection.get("radio_type")),
            ("Receive rate", f"{connection.get('receive_rate_mbps')} Mbps" if connection.get("receive_rate_mbps") is not None else None),
            ("Transmit rate", f"{connection.get('transmit_rate_mbps')} Mbps" if connection.get("transmit_rate_mbps") is not None else None),
            ("Network type", connection.get("network_type")),
        ]
        if analysis:
            hygiene = analysis.get("ssid_hygiene") or connection.get("ssid_hygiene") or {}
            hygiene_findings = hygiene.get("findings") or []
            detail_items.extend([
                ("BSSID", analysis.get("bssid")),
                ("Signal quality", f"{analysis.get('quality')}% ({analysis.get('signal_status', 'Unknown')})"),
                ("Frequency", f"{analysis.get('frequency')} MHz"),
                ("Band", f"{analysis.get('band')} ({analysis.get('band_status', 'Unknown')})"),
                ("Channel status", analysis.get("channel_status")),
                ("Security assessment", analysis.get("security_status")),
                ("SSID hygiene", ", ".join(hygiene_findings) if hygiene_findings else "No findings"),
            ])
        elif connection.get("ssid_hygiene"):
            findings = connection["ssid_hygiene"].get("findings") or []
            detail_items.append(("SSID hygiene", ", ".join(findings) if findings else "No findings"))
        for child in self.details_grid.winfo_children():
            child.destroy()
        color_by_label = {
            "Connection status": (GREEN_PALE, GREEN),
            "Connected interface": (BLUE_PALE, BLUE),
            "Channel status": (BLUE_PALE, BLUE),
            "Signal status": (BLUE_PALE, BLUE),
            "SSID": (SURFACE_ALT, INK),
            "Saved profile": (SURFACE_ALT, INK),
            "BSSID": (SURFACE_ALT, INK),
        }
        visible_items = [(label, value) for label, value in detail_items if value not in (None, "")]
        for index, (label, value) in enumerate(visible_items):
            tile_bg, accent = color_by_label.get(label, (SURFACE_ALT, BLUE))
            if label == "Security assessment":
                status = str(value).casefold()
                if status in ("very secure", "secure"):
                    tile_bg, accent = GREEN_PALE, GREEN
                elif status in ("weak", "unsecured"):
                    tile_bg, accent = (RED_PALE, RED) if status == "unsecured" else (AMBER_PALE, AMBER)
                else:
                    tile_bg, accent = AMBER_PALE, AMBER
            elif label == "Possible rogue AP" and value:
                tile_bg, accent = RED_PALE, RED
            elif label == "SSID hygiene" and str(value).casefold() not in ("no findings", ""):
                tile_bg, accent = AMBER_PALE, AMBER
            elif label == "Channel status" and str(value).casefold() == "overlapping":
                tile_bg, accent = AMBER_PALE, AMBER
            tile = tk.Frame(self.details_grid, bg=tile_bg, padx=10, pady=8)
            tile.grid(row=index // 3, column=index % 3, sticky="nsew", padx=3, pady=3)
            tk.Label(tile, text=label.upper(), bg=tile_bg, fg=accent,
                     font=("Segoe UI Semibold", 7)).pack(anchor="w")
            tk.Label(tile, text=str(value), bg=tile_bg, fg=INK, anchor="w", justify="left",
                     wraplength=245, font=("Segoe UI Semibold", 9)).pack(anchor="w", pady=(3, 0))
        if not analysis:
            row = (len(visible_items) + 2) // 3
            note = connection.get("analysis_error") or "Nearby scan did not return a matching SSID."
            tk.Label(self.details_grid, text=f"Additional nearby-network analysis is unavailable: {note}",
                     bg=AMBER_PALE, fg=AMBER, wraplength=850, justify="left",
                     font=("Segoe UI", 8), padx=10, pady=8).grid(
                         row=row, column=0, columnspan=3, sticky="ew", padx=3, pady=3)

        environment = connection.get("environment")
        for child in self.channel_scores_frame.winfo_children():
            child.destroy()
        if environment:
            status = environment.get("status", "Unknown congestion")
            recommended_channel = environment.get("recommended_channel")
            self.congestion_badge.configure(text=status)
            if "LOW" in status.upper():
                badge_colors = (GREEN_PALE, GREEN)
            elif "MODERATE" in status.upper():
                badge_colors = (AMBER_PALE, AMBER)
            elif "HIGH" in status.upper():
                badge_colors = (RED_PALE, RED)
            else:
                badge_colors = (BLUE_PALE, BLUE)
            self.congestion_badge.configure(bg=badge_colors[0], fg=badge_colors[1])
            score_parts = "     ".join(
                f"Channel {channel}: {score} congestion points"
                for channel, score in environment.get("channel_scores", {}).items()
            )
            if recommended_channel is None:
                summary = environment.get("message", "There is not enough nearby 2.4 GHz data for a recommendation.")
                chip_text = "No 2.4 GHz recommendation"
            else:
                summary = f"Recommended 2.4 GHz channel: {recommended_channel}  |  {environment.get('message', '')}"
                chip_text = f"Recommended channel {recommended_channel}"
            self.environment_var.set(f"{summary}\n{score_parts}")
            self._add_info_chip(self.channel_scores_frame, chip_text, BLUE_PALE, BLUE)
            if analysis:
                self._add_info_chip(self.channel_scores_frame,
                                    f"Current channel: {analysis.get('channel')} - {analysis.get('channel_status')}",
                                    SURFACE_ALT, INK)
                tk.Label(self.channel_scores_frame, text=analysis.get("channel_message", ""), bg=SURFACE,
                         fg=MUTED, font=("Segoe UI", 8)).pack(side="left", padx=(9, 0))
        else:
            self.congestion_badge.configure(text="Analyzer unavailable", bg=AMBER_PALE, fg=AMBER)
            reason = connection.get("analysis_error", "The environment analyzer returned no data.")
            self.environment_var.set(f"Channel recommendations unavailable: {reason}")

        for child in self.recommendations_frame.winfo_children():
            child.destroy()
        if analysis:
            groups = (
                ("Performance", "performance_recommendations"),
                ("Security", "security_recommendations"),
                ("Network identity", "identity_recommendations"),
                ("Configuration", "configuration_recommendations"),
                ("Channel", "channel_advice"),
                ("Band", "band_recommendations"),
            )
            for label, key in groups:
                items = analysis.get(key, [])
                if not items:
                    continue
                group = tk.Frame(self.recommendations_frame, bg=SURFACE_ALT, padx=11, pady=9)
                group.pack(fill="x", pady=3)
                tk.Label(group, text=label.upper(), bg=SURFACE_ALT, fg=BLUE,
                         font=("Segoe UI Semibold", 7)).pack(anchor="w")
                for recommendation in items:
                    tk.Label(group, text=f"•  {recommendation}", bg=SURFACE_ALT, fg=INK,
                             wraplength=850, justify="left", anchor="w",
                             font=("Segoe UI", 8)).pack(fill="x", anchor="w", pady=(4, 0))
        elif connection.get("analysis_error"):
            tk.Label(self.recommendations_frame,
                     text=f"Nearby-network recommendations could not be generated: {connection['analysis_error']}",
                     bg=SURFACE, fg=MUTED, wraplength=850, justify="left",
                     font=("Segoe UI", 8)).pack(anchor="w")
        else:
            tk.Label(self.recommendations_frame,
                     text="No matching network analysis is available for this scan.",
                     bg=SURFACE, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w")

        measured_recommendations = connection.get("performance_recommendations", [])
        if measured_recommendations:
            self._render_recommendation_group("Measured performance", measured_recommendations)
        elif connection.get("performance_metrics"):
            from performance_tests import get_performance_recommendations
            recommendations = get_performance_recommendations(connection["performance_metrics"], connection)
            connection["performance_recommendations"] = recommendations
            self._render_recommendation_group("Measured performance", recommendations)

        if not analysis and connection.get("channel_advice"):
            self._render_recommendation_group("Connected channel", connection["channel_advice"])

        for item in self.nearby_tree.get_children():
            self.nearby_tree.delete(item)
        networks = connection.get("nearby_networks", [])
        self._nearby_by_id = {}
        for index, network in enumerate(sorted(networks, key=lambda n: n.get("quality", 0), reverse=True)):
            item_id = str(index)
            self._nearby_by_id[item_id] = network
            self.nearby_tree.insert("", "end", iid=item_id, values=(
                network.get("ssid", "<Hidden>"), network.get("bssid", "Unknown"),
                f"{network.get('quality', 0)}%", network.get("security_status", "Unknown"),
                network.get("band", "Unknown"), network.get("channel", "Unknown"),
                network.get("channel_status", "Unknown"),
                "Possible rogue AP" if network.get("rogue_ap_suspected") else
                "Default SSID" if (network.get("ssid_hygiene") or {}).get("default_name") else "",
            ))
        if not networks:
            self._set_nearby_details(connection.get("analysis_error", "Nearby networks were not returned by the analyzer."))
        else:
            self._set_nearby_details("Select a nearby network to inspect all analyzer fields and its recommendations.")

    @staticmethod
    def _add_info_chip(parent, text, background, foreground):
        tk.Label(parent, text=text, bg=background, fg=foreground,
                 padx=9, pady=5, font=("Segoe UI Semibold", 8)).pack(side="left", padx=(0, 7))

    def _render_recommendation_group(self, label, items):
        group = tk.Frame(self.recommendations_frame, bg=SURFACE_ALT, padx=11, pady=9)
        group.pack(fill="x", pady=3)
        tk.Label(group, text=label.upper(), bg=SURFACE_ALT, fg=BLUE,
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        for recommendation in items:
            tk.Label(group, text=f"•  {recommendation}", bg=SURFACE_ALT, fg=INK,
                     wraplength=850, justify="left", anchor="w",
                     font=("Segoe UI", 8)).pack(fill="x", anchor="w", pady=(4, 0))

    def _set_nearby_details(self, text):
        self.nearby_details.configure(state="normal")
        self.nearby_details.delete("1.0", "end")
        self.nearby_details.insert("1.0", text)
        self.nearby_details.configure(state="disabled")

    def _show_nearby_details(self, _event=None):
        selected = self.nearby_tree.selection()
        if not selected:
            return
        network = self._nearby_by_id.get(selected[0])
        if not network:
            return
        scalar_fields = (
            ("Network", "ssid"), ("BSSID", "bssid"), ("Signal", "signal"),
            ("Signal quality", "quality"), ("Signal status", "signal_status"),
            ("Encryption", "encryption"), ("Security status", "security_status"),
            ("Security message", "security_message"), ("Frequency", "frequency"),
            ("Band", "band"), ("Band status", "band_status"),
            ("Channel", "channel"), ("Channel status", "channel_status"),
            ("Channel message", "channel_message"),
            ("Possible rogue AP", "rogue_ap_suspected"),
            ("SSID hygiene", "ssid_hygiene"),
        )
        lines = [f"{label}: {network.get(key, 'Unknown')}" for label, key in scalar_fields]
        for label, key in (("Performance", "performance_recommendations"),
                           ("Security", "security_recommendations"),
                           ("Network identity", "identity_recommendations"),
                           ("Configuration", "configuration_recommendations"),
                           ("Channel", "channel_advice"),
                           ("Band", "band_recommendations")):
            lines.append(f"\n{label} recommendations:")
            lines.extend(f"  - {tip}" for tip in network.get(key, []))
        self._set_nearby_details("\n".join(lines))

    def _render_security_alert(self, connection):
        auth = str(connection.get("authentication", "Unknown"))
        upper_auth = auth.upper()
        cipher = str(connection.get("cipher", "Unknown"))
        if connection.get("rogue_ap_suspected"):
            title = "High risk - a possible rogue access point is using this SSID"
            body = ("Nearby access points advertise this same SSID with a materially weaker security configuration. "
                "Do not trust this connection until you verify the BSSID with the network owner.")
            background, foreground, icon = RED_PALE, RED, "!"
        elif "OPEN" in upper_auth or upper_auth in ("NONE", "UNKNOWN"):
            title = "High risk - this Wi-Fi appears open or its security is unknown"
            body = ("On an open network, nearby people may be able to monitor or intercept traffic that is not encrypted by the website or app. "
                    "Avoid sensitive activity; use a trusted VPN or switch to WPA2/WPA3-protected Wi-Fi.")
            background, foreground, icon = RED_PALE, RED, "!"
        elif "WEP" in upper_auth or ("WPA" in upper_auth and "WPA2" not in upper_auth and "WPA3" not in upper_auth):
            title = "Needs attention - this network uses an older protocol"
            body = (f"The reported authentication is {auth}, which provides weaker protection. If you manage the router, "
                    "switch to WPA2-AES or WPA3 and keep its firmware current.")
            background, foreground, icon = AMBER_PALE, AMBER, "!"
        elif "WPA2" in upper_auth or "WPA3" in upper_auth:
            title = f"Protected connection - {auth}"
            body = (f"Your connection reports {auth} with {cipher} encryption. Keep your router firmware current and use a strong, unique password. "
                    "Wi-Fi protection complements, but does not replace, HTTPS and end-to-end encryption.")
            background, foreground, icon = GREEN_PALE, GREEN, "✓"
        else:
            title = f"Review this connection - {auth}"
            body = ("WISE could not identify the authentication standard confidently. Check the router settings; WPA3 or WPA2-AES is recommended. "
                    "Avoid sensitive activity until you confirm the network is protected.")
            background, foreground, icon = AMBER_PALE, AMBER, "i"
        self.alert_card.configure(bg=background, highlightbackground=background)
        for child in self.alert_card.winfo_children():
            child.configure(bg=background)
        self.alert_icon.configure(text=icon, bg=SURFACE, fg=foreground)
        self.alert_title_var.set(title)
        self.alert_body_var.set(body)

    def _recalculate_current(self):
        if self.connection is not None:
            self._save_assessment()

    def _save_assessment(self):
        self.score_info = score_connection(
            self.connection,
            password_policy_ok=self.password_var.get(),
            router_admin_password_ok=self.admin_password_var.get(),
        )
        # Render the score before storage so a database problem never hides the
        # result of an otherwise successful connected-interface scan.
        self._animate_score(self.score_info["total"])
        self._animate_bars(self.score_info)
        connection_ref = self.connection
        connection_snapshot = dict(self.connection)
        score_snapshot = dict(self.score_info)
        update_id = self.latest_scan_id
        user_id = self.user["id"]

        def saved_assessment(saved):
            if self.connection is not connection_ref:
                self.refresh_history()
                return
            self.latest_scan_id = saved["id"]
            previous = saved.get("previous")
            previous_score = {"total": previous["score"]} if previous else None
            change = compare_scores(previous_score, score_snapshot)
            self.score_change_var.set(change["label"])
            self.status_var.set(f"Assessment saved for {connection_ref.get('ssid', 'Unknown network')}.")
            self.refresh_history()
            if "nearby_networks" in self.connection and "nearby_networks" not in connection_snapshot:
                self._persist_analysis()

        def save_failed(error):
            self.score_change_var.set("Score calculated; scan history could not be saved")
            self.status_var.set(f"Score calculated but could not be saved: {error}")
            messagebox.showerror(
                "Scan history unavailable",
                f"WISE calculated a score of {score_snapshot['total']} out of 100, but could not save it.\n\n{error}",
            )

        self._run_api_task(
            lambda: database.save_scan(connection_snapshot, score_snapshot, update_id=update_id,
                                       user_id=user_id,
                                       separate=self.separate_scan_history_var.get()),
            saved_assessment,
            save_failed,
        )

    def _update_report_summary(self):
        if not hasattr(self, "report_summary_var"):
            return
        if self.connection is None or self.score_info is None:
            self.report_summary_var.set("Run a Wi-Fi scan to prepare an assessment report.")
            self.report_details_var.set("")
            return
        self.report_summary_var.set(
            f"{self.connection.get('ssid', 'Unknown network')} | Overall score: {self.score_info['total']}/100"
        )
        self.report_details_var.set(" | ".join(
            f"{row['category']}: {row['earned']}/{row['possible']}"
            for row in self.score_info.get("breakdown", [])
        ))

    def _persist_analysis(self):
        if self.connection is None or self.score_info is None or self.latest_scan_id is None or self.user is None:
            return
        connection_snapshot = dict(self.connection)
        score_snapshot = dict(self.score_info)
        update_id = self.latest_scan_id
        user_id = self.user["id"]
        self._run_api_task(
            lambda: database.save_scan(connection_snapshot, score_snapshot,
                                       update_id=update_id, user_id=user_id),
            lambda _saved: self.status_var.set("Nearby analysis saved."),
            lambda error: self.status_var.set(f"Nearby analysis could not be stored: {error}"),
        )

    def refresh_history(self):
        if not hasattr(self, "history_tree") or self.user is None:
            return

        user_id = self.user["id"]

        def show_history(rows):
            if self.user is None or self.user["id"] != user_id:
                return
            try:
                self.history_rows = rows
                self.history_summary_var.set(f"{len(rows)} saved assessment{'s' if len(rows) != 1 else ''}")
                self._render_history_rows()
                self._render_trend_chart(rows)
            except Exception as error:
                self.status_var.set(f"Database error: {error}")

        def history_failed(error):
            self.status_var.set(f"Database error: {error}")

        self._run_api_task(lambda: database.list_scans(user_id), show_history, history_failed)

    def _render_history_rows(self):
        if not hasattr(self, "history_tree"):
            return
        query = self.history_filter_var.get().strip().casefold()
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        for row in self.history_rows:
            if query and query not in str(row.get("ssid", "")).casefold():
                continue
            self.history_tree.insert("", "end", iid=str(row["id"]), values=(
                row["scanned_at"].replace("T", " "), row["ssid"], f"{row['score']} / 100",
                f"{row['protocol_score']} / 50", f"{row['company_score']} / 20",
                f"{row['other_score']} / 30"))

    def compare_selected_scans(self):
        selected = self.history_tree.selection()
        if len(selected) != 2:
            messagebox.showinfo("Select two scans", "Select exactly two assessments to compare.")
            return
        rows_by_id = {str(row["id"]): row for row in self.history_rows}
        first, second = (rows_by_id.get(item) for item in selected)
        if first is None or second is None:
            return
        lines = [f"{first['ssid']} vs {second['ssid']}",
                 f"Overall: {first['score']} → {second['score']} ({second['score'] - first['score']:+d})",
                 f"Security: {first['protocol_score']} → {second['protocol_score']} ({second['protocol_score'] - first['protocol_score']:+d})",
                 f"Configuration: {first['company_score']} → {second['company_score']} ({second['company_score'] - first['company_score']:+d})",
                 f"Performance: {first['other_score']} → {second['other_score']} ({second['other_score'] - first['other_score']:+d})"]
        messagebox.showinfo("Assessment comparison", "\n".join(lines))

    def export_history_csv(self):
        if not self.history_rows:
            messagebox.showinfo("No history", "There are no assessments to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export scan history", defaultextension=".csv",
            filetypes=(("CSV file", "*.csv"),), initialfile="wise-scan-history.csv",
        )
        if not path:
            return
        query = self.history_filter_var.get().strip().casefold()
        rows = [row for row in self.history_rows
                if not query or query in str(row.get("ssid", "")).casefold()]

        def write_csv():
            with open(path, "w", newline="", encoding="utf-8-sig") as output:
                writer = csv.writer(output)
                writer.writerow(("Date / time", "SSID", "Overall", "Security", "Configuration", "Performance"))
                for row in rows:
                    writer.writerow((row["scanned_at"], row["ssid"], row["score"], row["protocol_score"],
                                     row["company_score"], row["other_score"]))
            return path

        self._run_api_task(write_csv, lambda saved: self.status_var.set(f"CSV exported to {saved}."),
                           lambda error: messagebox.showerror("CSV export failed", str(error)))

    def open_saved_scan(self, _event=None):
        selected = self.history_tree.selection()
        if not selected:
            return
        record_id = int(selected[0])
        user_id = self.user["id"]

        def load_record():
            record = database.get_scan(record_id, user_id)
            rows = database.list_scans(user_id) if record is not None else []
            return record, rows

        def show_record(result):
            record, all_rows = result
            if self.user is None or self.user["id"] != user_id:
                return
            if record is None:
                return
            self._display_saved_scan(record, all_rows)

        self._run_api_task(load_record, show_record,
                           lambda error: self.status_var.set(f"Could not open saved scan: {error}"))

    def _display_saved_scan(self, record, all_rows):
        if record is None:
            return
        self.latest_scan_id = record["id"]
        self.viewing_saved_scan = True
        self.connection = record["connection"]
        self.score_info = record["score_details"]
        self.admin_password_var.set(self.score_info.get("router_admin_password_ok", False))
        self.password_var.set(self.score_info.get("password_policy_ok", False))
        self.ssid_var.set(record["ssid"])
        connection = self.connection
        self.performance_summary_var.set(self._format_performance(connection.get("performance_metrics")))
        self.metric_vars["security"].set(connection.get("authentication", "Unknown"))
        signal = connection.get("signal_percent")
        self.metric_vars["signal"].set(f"{signal}%" if signal is not None else "Unknown")
        self.metric_vars["cipher"].set(connection.get("cipher", "Unknown"))
        self.metric_vars["channel"].set(str(connection.get("channel") or "Unknown"))
        self.connection_badge.configure(text="●  Saved scan", bg=BLUE_PALE, fg=BLUE)
        self._render_security_alert(connection)
        self._render_backend_details(connection)
        self._animate_score(record["score"])
        self._animate_bars(self.score_info)
        earlier = [row for row in all_rows if row["network_key"] == record["network_key"]
                   and (row["scanned_at"], row["id"]) < (record["scanned_at"], record["id"])]
        if earlier:
            previous = max(earlier, key=lambda row: (row["scanned_at"], row["id"]))
            self.score_change_var.set(compare_scores({"total": previous["score"]}, self.score_info)["label"])
        else:
            self.score_change_var.set("Your first scan sets a baseline")
        self.show_page("dashboard")
        self.status_var.set(f"Reviewing saved scan from {record['scanned_at'].replace('T', ' ')}.")
        self.performance_summary_var.set(self._format_performance(self.connection.get("performance_metrics")))
        self._update_report_summary()

    def delete_selected_scan(self):
        selected = self.history_tree.selection()
        if not selected:
            messagebox.showinfo("Select a scan", "Choose a saved assessment first.")
            return
        if not messagebox.askyesno("Delete assessment", "Delete this saved assessment from history?"):
            return
        record_ids = {int(item) for item in selected}
        user_id = self.user["id"]

        def deleted(_result):
            if self.latest_scan_id in record_ids:
                self.latest_scan_id = None
            self.refresh_history()
            self.status_var.set(f"Deleted {len(record_ids)} assessment{'s' if len(record_ids) != 1 else ''}.")

        self._run_api_task(
            lambda: [database.delete_scan(record_id, user_id) for record_id in record_ids], deleted,
                           lambda error: messagebox.showerror(
                               "Delete failed", f"The saved assessment could not be deleted.\n\n{error}"
                           )
        )

    def delete_all_history(self):
        user_id = self.user["id"]

        def confirm_clear(rows):
            if not rows:
                messagebox.showinfo("No history", "There are no saved assessments to clear.")
                return
            if not messagebox.askyesno("Clear history", "Permanently delete all saved Wi-Fi assessments?"):
                return

            def cleared(_result):
                self.latest_scan_id = None
                self.refresh_history()
                self.status_var.set("Scan history cleared.")

            self._run_api_task(lambda: database.delete_all_scans(user_id), cleared,
                               lambda error: messagebox.showerror(
                                   "Clear failed", f"Scan history could not be cleared.\n\n{error}"
                               ))

        self._run_api_task(lambda: database.list_scans(user_id), confirm_clear,
                           lambda error: messagebox.showerror(
                               "History unavailable", f"WISE could not read scan history.\n\n{error}"
                           ))


if __name__ == "__main__":
    WiseApp().mainloop()
