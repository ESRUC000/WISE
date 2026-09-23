"""Modern Tkinter desktop interface for WISE Wi-Fi security scoring."""

import threading
import tkinter as tk
from tkinter import messagebox, ttk

import database
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
        self.company_var = tk.BooleanVar(value=False)
        self.password_var = tk.BooleanVar(value=False)
        self.current_page = "dashboard"
        self.scan_animation_id = None
        self.score_animation_id = None
        self.score_ring_value = 0
        self.score_rows = {}
        self.nav_buttons = {}
        self.analyzed_network = None
        self.environment = None
        self.scan_session = 0

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
        self.show_page("dashboard")
        self.refresh_history()
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
        mark.create_oval(2, 2, 32, 32, fill=BLUE, outline="")
        mark.create_arc(9, 9, 25, 25, start=35, extent=110, style="arc", outline="white", width=2)
        mark.create_arc(6, 6, 28, 28, start=35, extent=110, style="arc", outline="#AFCBFF", width=2)
        tk.Label(brand, text="WISE", bg=NAVY, fg="white", font=("Segoe UI", 17, "bold")).pack(side="left", padx=(10, 0))
        tk.Label(self.sidebar, text="WI-FI SECURITY", bg=NAVY, fg="#8293AA",
                 font=("Segoe UI Semibold", 8)).pack(anchor="w", padx=23, pady=(16, 9))

        self._nav_button("dashboard", "◉", "Overview")
        self._nav_button("history", "◷", "Scan history")

        spacer = tk.Frame(self.sidebar, bg=NAVY)
        spacer.pack(fill="both", expand=True)
        side_info = tk.Frame(self.sidebar, bg=NAVY_2, padx=13, pady=12)
        side_info.pack(fill="x", padx=13, pady=15)
        tk.Label(side_info, text="LOCAL & PRIVATE", bg=NAVY_2, fg="#C6D6EC",
                 font=("Segoe UI Semibold", 8)).pack(anchor="w")
        tk.Label(side_info, text="Your scan history stays on this device.", bg=NAVY_2, fg="#9EB0C8",
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

        self.status_var = tk.StringVar(value="Ready when you are. Scan to check your connected Wi-Fi.")
        footer = tk.Frame(self.main_area, bg=BG, padx=25, pady=7)
        footer.pack(fill="x", side="bottom")
        tk.Label(footer, textvariable=self.status_var, bg=BG, fg=MUTED,
                 font=("Segoe UI", 8), anchor="w").pack(fill="x")

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
        self.dashboard.pack_forget()
        self.history.pack_forget()
        target = self.dashboard if page == "dashboard" else self.history
        target.pack(fill="both", expand=True)
        self.breadcrumb_var.set("Overview" if page == "dashboard" else "Scan history")
        for key, button in self.nav_buttons.items():
            active = key == page
            button.configure(bg=NAVY_2 if active else NAVY, fg="white" if active else "#AFC0D6")

    def _card(self, parent, **kwargs):
        return tk.Frame(parent, bg=SURFACE, highlightbackground=LINE, highlightthickness=1, **kwargs)

    def _dashboard_mousewheel(self, event):
        if self.current_page == "dashboard" and self.dashboard_canvas.winfo_exists():
            self.dashboard_canvas.yview_scroll(int(-event.delta / 120), "units")

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

        self.scan_button = tk.Button(
            heading, text="  Scan network  ", command=self.start_scan,
            bg=BLUE, fg="white", activebackground=BLUE_DARK, activeforeground="white",
            relief="flat", bd=0, padx=13, pady=10, cursor="hand2",
            font=("Segoe UI Semibold", 9),
        )
        self.scan_button.pack(side="right", padx=(12, 0), pady=(2, 0))

        top_cards = tk.Frame(page, bg=BG)
        top_cards.pack(fill="x")
        score_card = self._card(top_cards, padx=19, pady=18, width=262, height=235)
        score_card.pack(side="left", fill="y", padx=(0, 13))
        score_card.pack_propagate(False)
        tk.Label(score_card, text="SECURITY SCORE", bg=SURFACE, fg=MUTED,
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

        self.details_panel = self._card(page, padx=18, pady=15)
        self.details_panel.pack(fill="x", pady=(0, 13))
        details_heading = tk.Frame(self.details_panel, bg=SURFACE)
        details_heading.pack(fill="x", pady=(0, 10))
        tk.Label(details_heading, text="Connection details", bg=SURFACE, fg=INK,
                 font=("Segoe UI Semibold", 11)).pack(side="left")
        tk.Label(details_heading, text="LIVE INTERFACE + ANALYZER", bg=SURFACE, fg=BLUE,
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
        nearby_columns = ("ssid", "bssid", "quality", "security", "band", "channel", "channel_status")
        self.nearby_tree = ttk.Treeview(nearby_card, columns=nearby_columns, show="headings", height=5,
                                        selectmode="browse", style="Wise.Treeview")
        for column, label, width in (("ssid", "SSID", 150), ("bssid", "BSSID", 145),
                                      ("quality", "QUALITY", 82), ("security", "SECURITY", 105),
                                      ("band", "BAND", 85), ("channel", "CHANNEL", 80),
                                      ("channel_status", "CHANNEL STATUS", 130)):
            self.nearby_tree.heading(column, text=label)
            self.nearby_tree.column(column, width=width, anchor="w" if column in ("ssid", "bssid") else "center")
        self.nearby_tree.pack(fill="x")
        self.nearby_tree.bind("<<TreeviewSelect>>", self._show_nearby_details)
        self.nearby_details = tk.Text(nearby_card, height=11, wrap="word", bg=SURFACE_ALT,
                                      fg=INK, relief="flat", padx=10, pady=8,
                                      font=("Consolas", 8), state="disabled")
        self.nearby_details.pack(fill="x", pady=(9, 0))

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
        for key, label, possible in (("protocol", "Security protocol", 60),
                                     ("company_and_password", "Network and password", 20),
                                     ("other", "Other safeguards", 20)):
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
        tk.Label(ownership, text="Your answers contribute 20 points. WISE cannot inspect company policy or read your Wi-Fi password.",
                 bg=SURFACE, fg=MUTED, wraplength=260, justify="left",
                 font=("Segoe UI", 8)).pack(anchor="w", pady=(6, 11))
        self.company_check = self._themed_check(ownership, "This is not a company-managed network", self.company_var)
        self.company_check.pack(anchor="w", fill="x", pady=4)
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
        self._action_button(actions, "Delete selected", self.delete_selected_scan, RED_PALE, RED).pack(side="left", padx=4)
        self._action_button(actions, "Clear history", self.delete_all_history, SURFACE, MUTED).pack(side="left", padx=4)

        summary = self._card(self.history, padx=17, pady=14)
        summary.pack(fill="x", pady=(0, 13))
        self.history_summary_var = tk.StringVar(value="No saved scans yet")
        tk.Label(summary, textvariable=self.history_summary_var, bg=SURFACE, fg=INK,
                 font=("Segoe UI Semibold", 9)).pack(anchor="w")
        panel = self._card(self.history, padx=10, pady=10)
        panel.pack(fill="both", expand=True)
        columns = ("date", "ssid", "score", "protocol", "company", "other")
        self.history_tree = ttk.Treeview(panel, columns=columns, show="headings",
                                         selectmode="browse", style="Wise.Treeview")
        headers = (("date", "DATE / TIME", 190), ("ssid", "NETWORK", 190),
                   ("score", "SCORE", 115), ("protocol", "PROTOCOL", 115),
                   ("company", "NETWORK / PASSWORD", 150), ("other", "OTHER", 100))
        for column, label, width in headers:
            self.history_tree.heading(column, text=label)
            self.history_tree.column(column, width=width, anchor="w" if column in ("date", "ssid") else "center")
        self.history_tree.pack(fill="both", expand=True)
        self.history_tree.bind("<Double-1>", self.open_saved_scan)
        tk.Label(panel, text="Double-click a scan to open its details on the overview page.",
                 bg=SURFACE, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w", pady=(9, 2))

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
        targets = {}
        for item in score_info["breakdown"]:
            key = {"Security protocol": "protocol", "Company SSID/password": "company_and_password",
                   "Other safeguards": "other"}.get(item["category"])
            if key in self.score_rows:
                value_var, bar, note_var = self.score_rows[key]
                value_var.set(f"{item['earned']} / {item['possible']}")
                note_var.set(item["note"])
                targets[key] = (bar, int(item["earned"]), int(bar["value"]))
        for frame in range(1, 15):
            def draw(frame=frame):
                for bar, target, start in targets.values():
                    bar["value"] = round(start + (target - start) * frame / 14)
            self.after(18 * frame, draw)

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
            self.after(0, lambda: self._on_connection_read(session, connection))
        except Exception as error:
            self.after(0, lambda: self._scan_failed(str(error)))
            return

        # Do the optional nearby scan only after the connected-network score has
        # been displayed and saved. PyWiFi may be slower or unavailable on a host.
        try:
            from analyzer import analyze
            networks, environment = analyze()
            self.after(0, lambda: self._apply_analysis(session, connection, networks, environment, None))
        except Exception as analysis_error:
            self.after(0, lambda: self._apply_analysis(session, connection, [], None, str(analysis_error)))

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
            active_ssid = connection.get("ssid", "").strip().casefold()
            matches = [network for network in networks
                       if str(network.get("ssid", "")).strip().casefold() == active_ssid]
            if matches:
                connection["analysis"] = max(matches, key=lambda network: network.get("quality", 0))
            connection["nearby_networks"] = networks
            connection["environment"] = environment
        self.connection.update(connection)
        self._render_backend_details(self.connection)
        # Persist the analyzer payload into the existing scan record.
        if self.latest_scan_id is not None and self.score_info is not None:
            try:
                database.save_scan(self.connection, self.score_info, update_id=self.latest_scan_id)
            except Exception as save_error:
                self.status_var.set(f"Score saved, but detailed scan data could not be stored: {save_error}")
                return
        self.status_var.set(
            f"Connected Wi-Fi score saved. Nearby analysis {('unavailable: ' + error) if error else 'updated.'}"
        )

    def _scan_failed(self, error):
        self.scan_button.configure(state="normal", text="  Scan network  ")
        self.network_status.configure(text="Scan unavailable", bg=AMBER_PALE, fg=AMBER)
        self.status_var.set("Could not read the current Wi-Fi connection.")
        messagebox.showerror("Wi-Fi scan failed", error)

    def _show_connection(self, connection):
        self.connection = connection
        self.latest_scan_id = None
        self.scan_button.configure(state="normal", text="  Scan network  ")
        self.company_var.set(False)
        self.password_var.set(False)
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
        self._save_assessment()

    def _render_backend_details(self, connection):
        analysis = connection.get("analysis") or {}
        self.analyzed_network = analysis or None
        self.environment = connection.get("environment")

        detail_items = [
            ("Connected interface", connection.get("state")),
            ("SSID", connection.get("ssid")),
            ("Saved profile", connection.get("profile")),
            ("Authentication", connection.get("authentication")),
            ("Cipher", connection.get("cipher")),
            ("Signal", f"{connection.get('signal_percent')}%" if connection.get("signal_percent") is not None else None),
            ("RSSI", f"{connection.get('rssi')} dBm" if connection.get("rssi") is not None else None),
            ("Channel", connection.get("channel")),
            ("Radio type", connection.get("radio_type")),
            ("Receive rate", f"{connection.get('receive_rate_mbps')} Mbps" if connection.get("receive_rate_mbps") is not None else None),
            ("Transmit rate", f"{connection.get('transmit_rate_mbps')} Mbps" if connection.get("transmit_rate_mbps") is not None else None),
        ]
        if analysis:
            detail_items.extend([
                ("BSSID", analysis.get("bssid")),
                ("Signal quality", f"{analysis.get('quality')}% ({analysis.get('signal_status', 'Unknown')})"),
                ("Frequency", f"{analysis.get('frequency')} MHz"),
                ("Band", f"{analysis.get('band')} ({analysis.get('band_status', 'Unknown')})"),
                ("Channel status", analysis.get("channel_status")),
                ("Security assessment", analysis.get("security_status")),
            ])
        for child in self.details_grid.winfo_children():
            child.destroy()
        color_by_label = {
            "Connected interface": (GREEN_PALE, GREEN),
            "Security assessment": (GREEN_PALE, GREEN),
            "Channel status": (BLUE_PALE, BLUE),
            "Signal status": (BLUE_PALE, BLUE),
            "SSID": (SURFACE_ALT, INK),
            "Saved profile": (SURFACE_ALT, INK),
            "BSSID": (SURFACE_ALT, INK),
        }
        visible_items = [(label, value) for label, value in detail_items if value not in (None, "")]
        for index, (label, value) in enumerate(visible_items):
            tile_bg, accent = color_by_label.get(label, (SURFACE_ALT, BLUE))
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
            self.congestion_badge.configure(text=status)
            self.congestion_badge.configure(
                bg=GREEN_PALE if "LOW" in status.upper() else AMBER_PALE if "MODERATE" in status.upper() else RED_PALE,
                fg=GREEN if "LOW" in status.upper() else AMBER if "MODERATE" in status.upper() else RED,
            )
            score_parts = "     ".join(
                f"Channel {channel}: {score} congestion points"
                for channel, score in environment.get("channel_scores", {}).items()
            )
            self.environment_var.set(
                f"Recommended 2.4 GHz channel: {environment.get('recommended_channel', 'Unknown')}  |  "
                f"{environment.get('message', '')}\n{score_parts}"
            )
            self._add_info_chip(self.channel_scores_frame,
                                f"Recommended channel {environment.get('recommended_channel', 'Unknown')}", BLUE_PALE, BLUE)
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
            ))
        if not networks:
            self._set_nearby_details(connection.get("analysis_error", "Nearby networks were not returned by the analyzer."))
        else:
            self._set_nearby_details("Select a nearby network to inspect all analyzer fields and its recommendations.")

    @staticmethod
    def _add_info_chip(parent, text, background, foreground):
        tk.Label(parent, text=text, bg=background, fg=foreground,
                 padx=9, pady=5, font=("Segoe UI Semibold", 8)).pack(side="left", padx=(0, 7))

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
        )
        lines = [f"{label}: {network.get(key, 'Unknown')}" for label, key in scalar_fields]
        for label, key in (("Performance", "performance_recommendations"),
                           ("Security", "security_recommendations"),
                           ("Channel", "channel_advice"),
                           ("Band", "band_recommendations")):
            lines.append(f"\n{label} recommendations:")
            lines.extend(f"  - {tip}" for tip in network.get(key, []))
        self._set_nearby_details("\n".join(lines))

    def _render_security_alert(self, connection):
        auth = str(connection.get("authentication", "Unknown"))
        upper_auth = auth.upper()
        cipher = str(connection.get("cipher", "Unknown"))
        if "OPEN" in upper_auth or upper_auth in ("NONE", "UNKNOWN"):
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
            company_network=self.company_var.get(),
            password_policy_ok=self.password_var.get(),
        )
        # Render the score before storage so a database problem never hides the
        # result of an otherwise successful connected-interface scan.
        self._animate_score(self.score_info["total"])
        self._animate_bars(self.score_info)
        try:
            saved = database.save_scan(self.connection, self.score_info, update_id=self.latest_scan_id)
            self.latest_scan_id = saved["id"]
            previous = None if saved.get("updated") else saved["previous"]
            previous_score = {"total": previous["score"]} if previous else None
            change = compare_scores(previous_score, self.score_info)
            self.score_change_var.set(change["label"])
            self.refresh_history()
        except Exception as error:
            self.score_change_var.set("Score calculated; scan history could not be saved")
            self.status_var.set(f"Score calculated but could not be saved: {error}")
            messagebox.showerror(
                "Scan history unavailable",
                f"WISE calculated a score of {self.score_info['total']} out of 100, but could not save it.\n\n{error}",
            )
            return
        self.status_var.set(f"Assessment saved for {self.connection['ssid']}.")

    def refresh_history(self):
        if not hasattr(self, "history_tree"):
            return
        try:
            for item in self.history_tree.get_children():
                self.history_tree.delete(item)
            rows = database.list_scans()
            for row in rows:
                self.history_tree.insert("", "end", iid=str(row["id"]), values=(
                    row["scanned_at"].replace("T", " "), row["ssid"], f"{row['score']} / 100",
                    f"{row['protocol_score']} / 60", f"{row['company_score']} / 20",
                    f"{row['other_score']} / 20"))
            self.history_summary_var.set(f"{len(rows)} saved assessment{'s' if len(rows) != 1 else ''}")
        except Exception as error:
            self.status_var.set(f"Database error: {error}")

    def open_saved_scan(self, _event=None):
        selected = self.history_tree.selection()
        if not selected:
            return
        record = database.get_scan(int(selected[0]))
        if record is None:
            return
        self.latest_scan_id = record["id"]
        self.connection = record["connection"]
        self.score_info = record["score_details"]
        self.company_var.set(self.score_info.get("company_network", False))
        self.password_var.set(self.score_info.get("password_policy_ok", False))
        self.ssid_var.set(record["ssid"])
        connection = self.connection
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
        all_rows = database.list_scans()
        earlier = [row for row in all_rows if row["ssid"].casefold() == record["ssid"].casefold()
                   and (row["scanned_at"], row["id"]) < (record["scanned_at"], record["id"])]
        if earlier:
            previous = max(earlier, key=lambda row: (row["scanned_at"], row["id"]))
            self.score_change_var.set(compare_scores({"total": previous["score"]}, self.score_info)["label"])
        else:
            self.score_change_var.set("Your first scan sets a baseline")
        self.show_page("dashboard")
        self.status_var.set(f"Reviewing saved scan from {record['scanned_at'].replace('T', ' ')}.")

    def delete_selected_scan(self):
        selected = self.history_tree.selection()
        if not selected:
            messagebox.showinfo("Select a scan", "Choose a saved assessment first.")
            return
        if not messagebox.askyesno("Delete assessment", "Delete this saved assessment from history?"):
            return
        record_id = int(selected[0])
        database.delete_scan(record_id)
        if record_id == self.latest_scan_id:
            self.latest_scan_id = None
        self.refresh_history()
        self.status_var.set("Assessment deleted.")

    def delete_all_history(self):
        if not database.list_scans():
            messagebox.showinfo("No history", "There are no saved assessments to clear.")
            return
        if not messagebox.askyesno("Clear history", "Permanently delete all saved Wi-Fi assessments?"):
            return
        database.delete_all_scans()
        self.latest_scan_id = None
        self.refresh_history()
        self.status_var.set("Scan history cleared.")


if __name__ == "__main__":
    WiseApp().mainloop()
