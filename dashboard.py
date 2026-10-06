import tkinter as tk


class SecurityDashboard:

    def __init__(self, parent):

        self.parent = parent

        self.window = tk.Toplevel(parent)

        self.window.title(
            "NIDS - Security Operations Dashboard"
        )

        self.window.geometry(
            "1050x750"
        )

        self.window.minsize(
            950,
            650
        )

        self.window.configure(
            bg="#111827"
        )

        self.create_dashboard()

    # =====================================================
    # CREATE DASHBOARD
    # =====================================================

    def create_dashboard(self):

        # =================================================
        # TITLE AREA
        # =================================================

        header_frame = tk.Frame(
            self.window,
            bg="#111827"
        )

        header_frame.pack(
            side="top",
            fill="x"
        )

        title = tk.Label(
            header_frame,
            text="SECURITY OPERATIONS DASHBOARD",
            font=("Arial", 22, "bold"),
            bg="#111827",
            fg="white"
        )

        title.pack(
            pady=(18, 3)
        )

        subtitle = tk.Label(
            header_frame,
            text="Network Intrusion Detection & Security Monitoring",
            font=("Arial", 10),
            bg="#111827",
            fg="#9ca3af"
        )

        subtitle.pack(
            pady=(0, 15)
        )

        # =================================================
        # FIXED BOTTOM BUTTON
        # =================================================

        bottom_frame = tk.Frame(
            self.window,
            bg="#111827",
            height=65
        )

        bottom_frame.pack(
            side="bottom",
            fill="x"
        )

        bottom_frame.pack_propagate(False)

        self.refresh_button = tk.Button(
            bottom_frame,
            text="REFRESH DASHBOARD",
            command=self.refresh_dashboard,
            bg="#2563eb",
            fg="white",
            activebackground="#1d4ed8",
            activeforeground="white",
            font=("Arial", 10, "bold"),
            width=22,
            height=1,
            cursor="hand2"
        )

        self.refresh_button.pack(
            pady=12
        )

        # =================================================
        # SCROLLABLE CONTENT AREA
        # =================================================

        outer_frame = tk.Frame(
            self.window,
            bg="#111827"
        )

        outer_frame.pack(
            side="top",
            fill="both",
            expand=True,
            padx=15,
            pady=5
        )

        # Canvas

        self.canvas = tk.Canvas(
            outer_frame,
            bg="#111827",
            highlightthickness=0
        )

        self.canvas.pack(
            side="left",
            fill="both",
            expand=True
        )

        # Scrollbar

        scrollbar = tk.Scrollbar(
            outer_frame,
            orient="vertical",
            command=self.canvas.yview
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        self.canvas.configure(
            yscrollcommand=scrollbar.set
        )

        # Content frame

        self.content_frame = tk.Frame(
            self.canvas,
            bg="#111827"
        )

        self.canvas_window = self.canvas.create_window(
            (0, 0),
            window=self.content_frame,
            anchor="nw"
        )

        self.content_frame.bind(
            "<Configure>",
            self.update_scroll_region
        )

        self.canvas.bind(
            "<Configure>",
            self.resize_canvas_content
        )

        # =================================================
        # STATISTICS CARDS
        # =================================================

        stats_frame = tk.Frame(
            self.content_frame,
            bg="#111827"
        )

        stats_frame.pack(
            fill="x",
            padx=5,
            pady=(5, 10)
        )

        self.packet_card = self.create_card(
            stats_frame,
            "TOTAL PACKETS",
            "0"
        )

        self.tcp_card = self.create_card(
            stats_frame,
            "TCP",
            "0"
        )

        self.udp_card = self.create_card(
            stats_frame,
            "UDP",
            "0"
        )

        self.icmp_card = self.create_card(
            stats_frame,
            "ICMP",
            "0"
        )

        self.alert_card = self.create_card(
            stats_frame,
            "ALERTS",
            "0"
        )

        # =================================================
        # THREAT CARDS
        # =================================================

        threat_cards = tk.Frame(
            self.content_frame,
            bg="#111827"
        )

        threat_cards.pack(
            fill="x",
            padx=5,
            pady=5
        )

        self.high_card = self.create_threat_card(
            threat_cards,
            "HIGH RISK",
            "0"
        )

        self.medium_card = self.create_threat_card(
            threat_cards,
            "MEDIUM RISK",
            "0"
        )

        self.low_card = self.create_threat_card(
            threat_cards,
            "LOW RISK",
            "0"
        )

        self.events_card = self.create_threat_card(
            threat_cards,
            "SECURITY EVENTS",
            "0"
        )

        # =================================================
        # INFORMATION AREA
        # =================================================

        content_area = tk.Frame(
            self.content_frame,
            bg="#111827"
        )

        content_area.pack(
            fill="both",
            expand=True,
            padx=5,
            pady=10
        )

        # =================================================
        # PROTOCOL STATISTICS
        # =================================================

        protocol_frame = tk.LabelFrame(
            content_area,
            text=" PROTOCOL STATISTICS ",
            font=("Arial", 11, "bold"),
            bg="#1f2937",
            fg="white",
            bd=1
        )

        protocol_frame.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 7)
        )

        self.protocol_text = tk.Text(
            protocol_frame,
            bg="#0f172a",
            fg="#60a5fa",
            font=("Consolas", 12),
            state="disabled",
            wrap="word",
            height=15
        )

        self.protocol_text.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        # =================================================
        # THREAT INFORMATION
        # =================================================

        threat_frame = tk.LabelFrame(
            content_area,
            text=" THREAT ANALYSIS ",
            font=("Arial", 11, "bold"),
            bg="#1f2937",
            fg="white",
            bd=1
        )

        threat_frame.pack(
            side="right",
            fill="both",
            expand=True,
            padx=(7, 0)
        )

        self.threat_text = tk.Text(
            threat_frame,
            bg="#0f172a",
            fg="#f87171",
            font=("Consolas", 12),
            state="disabled",
            wrap="word",
            height=15
        )

        self.threat_text.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        # =================================================
        # INITIAL DATA
        # =================================================

        self.update_dashboard(
            packets=0,
            tcp=0,
            udp=0,
            icmp=0,
            alerts=0,
            high=0,
            medium=0,
            low=0,
            alert_types={}
        )

    # =====================================================
    # SCROLL FUNCTIONS
    # =====================================================

    def update_scroll_region(self, event=None):

        self.canvas.configure(
            scrollregion=self.canvas.bbox("all")
        )

    def resize_canvas_content(self, event):

        self.canvas.itemconfig(
            self.canvas_window,
            width=event.width
        )

    # =====================================================
    # NORMAL STAT CARD
    # =====================================================

    def create_card(
        self,
        parent,
        title,
        value
    ):

        frame = tk.Frame(
            parent,
            bg="#1f2937",
            height=80
        )

        frame.pack(
            side="left",
            fill="both",
            expand=True,
            padx=4
        )

        title_label = tk.Label(
            frame,
            text=title,
            font=("Arial", 9, "bold"),
            bg="#1f2937",
            fg="#9ca3af"
        )

        title_label.pack(
            pady=(8, 0)
        )

        value_label = tk.Label(
            frame,
            text=value,
            font=("Arial", 21, "bold"),
            bg="#1f2937",
            fg="white"
        )

        value_label.pack(
            pady=3
        )

        return value_label

    # =====================================================
    # THREAT CARD
    # =====================================================

    def create_threat_card(
        self,
        parent,
        title,
        value
    ):

        frame = tk.Frame(
            parent,
            bg="#1f2937",
            height=70
        )

        frame.pack(
            side="left",
            fill="both",
            expand=True,
            padx=4
        )

        title_label = tk.Label(
            frame,
            text=title,
            font=("Arial", 9, "bold"),
            bg="#1f2937",
            fg="#9ca3af"
        )

        title_label.pack(
            pady=(8, 0)
        )

        value_label = tk.Label(
            frame,
            text=value,
            font=("Arial", 20, "bold"),
            bg="#1f2937",
            fg="#f87171"
        )

        value_label.pack()

        return value_label

    # =====================================================
    # UPDATE DASHBOARD
    # =====================================================

    def update_dashboard(
        self,
        packets,
        tcp,
        udp,
        icmp,
        alerts,
        high=0,
        medium=0,
        low=0,
        alert_types=None
    ):

        if alert_types is None:
            alert_types = {}

        # =================================================
        # MAIN CARDS
        # =================================================

        self.packet_card.config(
            text=str(packets)
        )

        self.tcp_card.config(
            text=str(tcp)
        )

        self.udp_card.config(
            text=str(udp)
        )

        self.icmp_card.config(
            text=str(icmp)
        )

        self.alert_card.config(
            text=str(alerts)
        )

        # =================================================
        # THREAT CARDS
        # =================================================

        self.high_card.config(
            text=str(high)
        )

        self.medium_card.config(
            text=str(medium)
        )

        self.low_card.config(
            text=str(low)
        )

        self.events_card.config(
            text=str(alerts)
        )

        # =================================================
        # PROTOCOL INFORMATION
        # =================================================

        self.protocol_text.config(
            state="normal"
        )

        self.protocol_text.delete(
            "1.0",
            "end"
        )

        self.protocol_text.insert(
            "end",
            "NETWORK PROTOCOL ANALYSIS\n"
        )

        self.protocol_text.insert(
            "end",
            "==============================\n\n"
        )

        self.protocol_text.insert(
            "end",
            f"Total Packets : {packets}\n\n"
        )

        self.protocol_text.insert(
            "end",
            f"TCP Packets   : {tcp}\n\n"
        )

        self.protocol_text.insert(
            "end",
            f"UDP Packets   : {udp}\n\n"
        )

        self.protocol_text.insert(
            "end",
            f"ICMP Packets  : {icmp}\n\n"
        )

        if packets > 0:

            tcp_percent = (
                tcp / packets
            ) * 100

            udp_percent = (
                udp / packets
            ) * 100

            icmp_percent = (
                icmp / packets
            ) * 100

            self.protocol_text.insert(
                "end",
                "PROTOCOL DISTRIBUTION\n"
            )

            self.protocol_text.insert(
                "end",
                "------------------------------\n\n"
            )

            self.protocol_text.insert(
                "end",
                f"TCP   : {tcp_percent:.1f}%\n"
            )

            self.protocol_text.insert(
                "end",
                f"UDP   : {udp_percent:.1f}%\n"
            )

            self.protocol_text.insert(
                "end",
                f"ICMP  : {icmp_percent:.1f}%\n"
            )

        self.protocol_text.config(
            state="disabled"
        )

        # =================================================
        # THREAT ANALYSIS
        # =================================================

        self.threat_text.config(
            state="normal"
        )

        self.threat_text.delete(
            "1.0",
            "end"
        )

        self.threat_text.insert(
            "end",
            "SECURITY THREAT ANALYSIS\n"
        )

        self.threat_text.insert(
            "end",
            "==============================\n\n"
        )

        self.threat_text.insert(
            "end",
            f"HIGH RISK     : {high}\n\n"
        )

        self.threat_text.insert(
            "end",
            f"MEDIUM RISK   : {medium}\n\n"
        )

        self.threat_text.insert(
            "end",
            f"LOW RISK      : {low}\n\n"
        )

        self.threat_text.insert(
            "end",
            f"TOTAL EVENTS  : {alerts}\n\n"
        )

        self.threat_text.insert(
            "end",
            "ALERT TYPES\n"
        )

        self.threat_text.insert(
            "end",
            "------------------------------\n\n"
        )

        if alert_types:

            for alert_type, count in alert_types.items():

                self.threat_text.insert(
                    "end",
                    f"{alert_type} : {count}\n"
                )

        else:

            self.threat_text.insert(
                "end",
                "No security events recorded.\n"
            )

        self.threat_text.config(
            state="disabled"
        )

    # =====================================================
    # REFRESH DASHBOARD
    # =====================================================

    def refresh_dashboard(self):

        if hasattr(
            self.parent,
            "update_dashboard"
        ):

            self.parent.update_dashboard()