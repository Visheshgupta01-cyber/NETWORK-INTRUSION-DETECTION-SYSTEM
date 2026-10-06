import tkinter as tk
from tkinter import ttk, messagebox

from packet_monitor import PacketMonitor
from detector import IntrusionDetector
from database import AlertDatabase
from report import ReportGenerator
from dashboard import SecurityDashboard


class NIDSApplication:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "Network Intrusion Detection System"
        )

        self.root.geometry(
            "1100x700"
        )

        self.root.minsize(
            950,
            600
        )

        self.root.configure(
            bg="#111827"
        )

        # =================================================
        # COMPONENTS
        # =================================================

        self.database = AlertDatabase()

        self.detector = IntrusionDetector()

        self.report_generator = ReportGenerator(
            self.database
        )

        self.packet_monitor = PacketMonitor(
            self.add_packet
        )

        # =================================================
        # COUNTERS
        # =================================================

        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.alert_count = 0

        # =================================================
        # DASHBOARD
        # =================================================

        self.dashboard_window = None

        # =================================================
        # CREATE GUI
        # =================================================

        self.create_gui()

        # =================================================
        # START AUTOMATIC DASHBOARD UPDATE
        # =================================================

        self.root.after(
            1000,
            self.update_dashboard
        )

        # =================================================
        # CLOSE EVENT
        # =================================================

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close_application
        )

    # =====================================================
    # CREATE GUI
    # =====================================================

    def create_gui(self):

        # -------------------------------------------------
        # HEADER
        # -------------------------------------------------

        header_frame = tk.Frame(
            self.root,
            bg="#111827"
        )

        header_frame.pack(
            fill="x",
            padx=20,
            pady=(20, 10)
        )

        title = tk.Label(
            header_frame,
            text="NETWORK INTRUSION DETECTION SYSTEM",
            font=("Arial", 22, "bold"),
            bg="#111827",
            fg="white"
        )

        title.pack()

        subtitle = tk.Label(
            header_frame,
            text="Real-Time Network Security Monitoring",
            font=("Arial", 11),
            bg="#111827",
            fg="#9ca3af"
        )

        subtitle.pack(
            pady=(5, 0)
        )

        # -------------------------------------------------
        # CONTROL BUTTONS
        # -------------------------------------------------

        control_frame = tk.Frame(
            self.root,
            bg="#111827"
        )

        control_frame.pack(
            fill="x",
            padx=20,
            pady=10
        )

        self.start_button = tk.Button(
            control_frame,
            text="START MONITORING",
            command=self.start_monitoring,
            bg="#16a34a",
            fg="white",
            activebackground="#15803d",
            activeforeground="white",
            font=("Arial", 10, "bold"),
            width=16,
            cursor="hand2"
        )

        self.start_button.pack(
            side="left",
            padx=5
        )

        self.stop_button = tk.Button(
            control_frame,
            text="STOP MONITORING",
            command=self.stop_monitoring,
            bg="#dc2626",
            fg="white",
            activebackground="#b91c1c",
            activeforeground="white",
            font=("Arial", 10, "bold"),
            width=16,
            cursor="hand2"
        )

        self.stop_button.pack(
            side="left",
            padx=5
        )

        self.dashboard_button = tk.Button(
            control_frame,
            text="DASHBOARD",
            command=self.open_dashboard,
            bg="#0891b2",
            fg="white",
            activebackground="#0e7490",
            activeforeground="white",
            font=("Arial", 10, "bold"),
            width=12,
            cursor="hand2"
        )

        self.dashboard_button.pack(
            side="left",
            padx=5
        )

        self.test_button = tk.Button(
            control_frame,
            text="TEST ALERT",
            command=self.test_alert,
            bg="#7c3aed",
            fg="white",
            activebackground="#6d28d9",
            activeforeground="white",
            font=("Arial", 10, "bold"),
            width=12,
            cursor="hand2"
        )

        self.test_button.pack(
            side="left",
            padx=5
        )

        self.history_button = tk.Button(
            control_frame,
            text="ALERT HISTORY",
            command=self.show_alert_history,
            bg="#374151",
            fg="white",
            activebackground="#4b5563",
            activeforeground="white",
            font=("Arial", 10, "bold"),
            width=14,
            cursor="hand2"
        )

        self.history_button.pack(
            side="left",
            padx=5
        )

        self.report_button = tk.Button(
            control_frame,
            text="EXPORT REPORT",
            command=self.export_report,
            bg="#ea580c",
            fg="white",
            activebackground="#c2410c",
            activeforeground="white",
            font=("Arial", 10, "bold"),
            width=14,
            cursor="hand2"
        )

        self.report_button.pack(
            side="left",
            padx=5
        )

        # -------------------------------------------------
        # STATUS
        # -------------------------------------------------

        status_frame = tk.Frame(
            self.root,
            bg="#1f2937"
        )

        status_frame.pack(
            fill="x",
            padx=20,
            pady=10
        )

        tk.Label(
            status_frame,
            text="STATUS",
            font=("Arial", 10, "bold"),
            bg="#1f2937",
            fg="#9ca3af"
        ).pack(
            side="left",
            padx=15,
            pady=12
        )

        self.status_label = tk.Label(
            status_frame,
            text="Monitoring Stopped",
            font=("Arial", 11, "bold"),
            bg="#1f2937",
            fg="#f87171"
        )

        self.status_label.pack(
            side="left"
        )

        # -------------------------------------------------
        # STATISTICS
        # -------------------------------------------------

        stats_frame = tk.Frame(
            self.root,
            bg="#111827"
        )

        stats_frame.pack(
            fill="x",
            padx=20,
            pady=10
        )

        self.packet_label = self.create_stat_box(
            stats_frame,
            "PACKETS",
            "0"
        )

        self.tcp_label = self.create_stat_box(
            stats_frame,
            "TCP",
            "0"
        )

        self.udp_label = self.create_stat_box(
            stats_frame,
            "UDP",
            "0"
        )

        self.icmp_label = self.create_stat_box(
            stats_frame,
            "ICMP",
            "0"
        )

        self.alert_label = self.create_stat_box(
            stats_frame,
            "ALERTS",
            "0"
        )

        # -------------------------------------------------
        # PACKET TABLE
        # -------------------------------------------------

        table_frame = tk.Frame(
            self.root,
            bg="#111827"
        )

        table_frame.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=10
        )

        columns = (
            "time",
            "source",
            "destination",
            "protocol",
            "port"
        )

        self.packet_table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings"
        )

        self.packet_table.heading(
            "time",
            text="TIME"
        )

        self.packet_table.heading(
            "source",
            text="SOURCE IP"
        )

        self.packet_table.heading(
            "destination",
            text="DESTINATION IP"
        )

        self.packet_table.heading(
            "protocol",
            text="PROTOCOL"
        )

        self.packet_table.heading(
            "port",
            text="PORT"
        )

        self.packet_table.column(
            "time",
            width=100
        )

        self.packet_table.column(
            "source",
            width=180
        )

        self.packet_table.column(
            "destination",
            width=180
        )

        self.packet_table.column(
            "protocol",
            width=120
        )

        self.packet_table.column(
            "port",
            width=100
        )

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.packet_table.yview
        )

        self.packet_table.configure(
            yscrollcommand=scrollbar.set
        )

        self.packet_table.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        # -------------------------------------------------
        # FOOTER
        # -------------------------------------------------

        footer = tk.Label(
            self.root,
            text="NIDS Educational Cybersecurity Project",
            font=("Arial", 9),
            bg="#111827",
            fg="#6b7280"
        )

        footer.pack(
            pady=5
        )

    # =====================================================
    # STAT BOX
    # =====================================================

    def create_stat_box(
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
            padx=5
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
            font=("Arial", 22, "bold"),
            bg="#1f2937",
            fg="white"
        )

        value_label.pack(
            pady=3
        )

        return value_label

    # =====================================================
    # START MONITORING
    # =====================================================

    def start_monitoring(self):

        try:

            self.packet_monitor.start()

            self.status_label.config(
                text="Monitoring Active",
                fg="#4ade80"
            )

            self.start_button.config(
                state="disabled"
            )

            print(
                "Monitoring started."
            )

        except Exception as e:

            messagebox.showerror(
                "Monitoring Error",
                str(e)
            )

    # =====================================================
    # STOP MONITORING
    # =====================================================

    def stop_monitoring(self):

        try:

            self.packet_monitor.stop()

            self.status_label.config(
                text="Monitoring Stopped",
                fg="#f87171"
            )

            self.start_button.config(
                state="normal"
            )

            print(
                "Monitoring stopped."
            )

        except Exception as e:

            print(
                "Stop monitoring error:",
                e
            )

    # =====================================================
    # ADD PACKET
    # =====================================================

    def add_packet(self, packet):

        self.packet_count += 1

        protocol = packet.get(
            "protocol",
            "IP"
        )

        if protocol == "TCP":

            self.tcp_count += 1

        elif protocol == "UDP":

            self.udp_count += 1

        elif protocol == "ICMP":

            self.icmp_count += 1

        # -------------------------------------------------
        # ADD PACKET TO TABLE
        # -------------------------------------------------

        self.root.after(
            0,
            lambda: self.packet_table.insert(
                "",
                0,
                values=(
                    packet.get("time", ""),
                    packet.get("source", ""),
                    packet.get("destination", ""),
                    packet.get("protocol", ""),
                    packet.get("port", "")
                )
            )
        )

        # -------------------------------------------------
        # UPDATE MAIN STATISTICS
        # -------------------------------------------------

        self.root.after(
            0,
            self.update_statistics
        )

        # -------------------------------------------------
        # DETECT THREAT
        # -------------------------------------------------

        try:

            alert = self.detector.analyze(
                packet
            )

            if alert:

                self.alert_count += 1

                self.database.save_alert(
                    alert
                )

                self.root.after(
                    0,
                    lambda a=alert:
                    self.show_alert(a)
                )

                self.root.after(
                    0,
                    self.update_statistics
                )

                self.root.after(
                    0,
                    self.update_dashboard
                )

        except Exception as e:

            print(
                "Detection error:",
                e
            )

    # =====================================================
    # UPDATE STATISTICS
    # =====================================================

    def update_statistics(self):

        self.packet_label.config(
            text=str(self.packet_count)
        )

        self.tcp_label.config(
            text=str(self.tcp_count)
        )

        self.udp_label.config(
            text=str(self.udp_count)
        )

        self.icmp_label.config(
            text=str(self.icmp_count)
        )

        self.alert_label.config(
            text=str(self.alert_count)
        )

    # =====================================================
    # SHOW ALERT
    # =====================================================

    def show_alert(self, alert):

        messagebox.showwarning(
            "SECURITY ALERT",
            (
                f"Threat Detected!\n\n"
                f"Type: {alert.get('type')}\n"
                f"Source: {alert.get('source')}\n"
                f"Risk: {alert.get('risk')}\n\n"
                f"{alert.get('message')}"
            )
        )

    # =====================================================
    # GET THREAT STATISTICS
    # =====================================================

    def get_threat_statistics(self):

        alerts = self.database.get_alerts()

        high = 0
        medium = 0
        low = 0

        alert_types = {}

        for alert in alerts:

            risk = str(
                alert[4]
            ).upper()

            if risk == "HIGH":

                high += 1

            elif risk == "MEDIUM":

                medium += 1

            elif risk == "LOW":

                low += 1

            alert_type = str(
                alert[2]
            )

            if alert_type not in alert_types:

                alert_types[alert_type] = 0

            alert_types[alert_type] += 1

        return (
            high,
            medium,
            low,
            alert_types
        )

    # =====================================================
    # OPEN DASHBOARD
    # =====================================================

    def open_dashboard(self):

        if (
            self.dashboard_window is not None
            and self.dashboard_window.window.winfo_exists()
        ):

            self.dashboard_window.window.lift()

            self.update_dashboard()

            return

        self.dashboard_window = SecurityDashboard(
            self.root
        )

        self.dashboard_window.window.protocol(
            "WM_DELETE_WINDOW",
            self.dashboard_closed
        )

        self.update_dashboard()

    # =====================================================
    # CLOSE DASHBOARD
    # =====================================================

    def dashboard_closed(self):

        if self.dashboard_window is not None:

            try:

                self.dashboard_window.window.destroy()

            except Exception:
                pass

        self.dashboard_window = None

    # =====================================================
    # LIVE DASHBOARD UPDATE
    # =====================================================

    def update_dashboard(self):

        if self.dashboard_window is not None:

            try:

                if not self.dashboard_window.window.winfo_exists():

                    self.dashboard_window = None

                else:

                    high, medium, low, alert_types = (
                        self.get_threat_statistics()
                    )

                    self.dashboard_window.update_dashboard(
                        self.packet_count,
                        self.tcp_count,
                        self.udp_count,
                        self.icmp_count,
                        self.alert_count,
                        high,
                        medium,
                        low,
                        alert_types
                    )

            except Exception as e:

                print(
                    "Dashboard update error:",
                    e
                )

        # -------------------------------------------------
        # RUN AGAIN AFTER 1 SECOND
        # -------------------------------------------------

        try:

            self.root.after(
                1000,
                self.update_dashboard
            )

        except Exception:
            pass

    # =====================================================
    # TEST ALERT
    # =====================================================

    def test_alert(self):

        alert = {
            "type": "Possible Port Scan",
            "source": "192.168.1.100",
            "ports": 20,
            "risk": "HIGH",
            "message": (
                "Test security alert generated "
                "for NIDS demonstration."
            )
        }

        self.alert_count += 1

        self.database.save_alert(
            alert
        )

        self.update_statistics()

        self.show_alert(
            alert
        )

        self.update_dashboard()

    # =====================================================
    # SHOW ALERT HISTORY
    # =====================================================

    def show_alert_history(self):

        alerts = self.database.get_alerts()

        history_window = tk.Toplevel(
            self.root
        )

        history_window.title(
            "NIDS - Alert History"
        )

        history_window.geometry(
            "950x500"
        )

        history_window.configure(
            bg="#111827"
        )

        title = tk.Label(
            history_window,
            text="SECURITY ALERT HISTORY",
            font=("Arial", 18, "bold"),
            bg="#111827",
            fg="white"
        )

        title.pack(
            pady=15
        )

        frame = tk.Frame(
            history_window,
            bg="#111827"
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=10
        )

        columns = (
            "id",
            "timestamp",
            "type",
            "source",
            "risk",
            "message"
        )

        tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings"
        )

        tree.heading(
            "id",
            text="ID"
        )

        tree.heading(
            "timestamp",
            text="TIMESTAMP"
        )

        tree.heading(
            "type",
            text="ALERT TYPE"
        )

        tree.heading(
            "source",
            text="SOURCE IP"
        )

        tree.heading(
            "risk",
            text="RISK"
        )

        tree.heading(
            "message",
            text="MESSAGE"
        )

        tree.column(
            "id",
            width=50
        )

        tree.column(
            "timestamp",
            width=150
        )

        tree.column(
            "type",
            width=150
        )

        tree.column(
            "source",
            width=130
        )

        tree.column(
            "risk",
            width=80
        )

        tree.column(
            "message",
            width=350
        )

        for alert in alerts:

            tree.insert(
                "",
                "end",
                values=alert
            )

        scrollbar = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=tree.yview
        )

        tree.configure(
            yscrollcommand=scrollbar.set
        )

        tree.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        # -------------------------------------------------
        # CLEAR HISTORY
        # -------------------------------------------------

        clear_button = tk.Button(
            history_window,
            text="CLEAR ALERT HISTORY",
            command=lambda:
            self.clear_history(
                history_window,
                tree
            ),
            bg="#dc2626",
            fg="white",
            activebackground="#b91c1c",
            activeforeground="white",
            font=("Arial", 10, "bold"),
            width=22,
            cursor="hand2"
        )

        clear_button.pack(
            pady=15
        )

    # =====================================================
    # CLEAR HISTORY
    # =====================================================

    def clear_history(
        self,
        window,
        tree
    ):

        answer = messagebox.askyesno(
            "Clear Alert History",
            "Are you sure you want to delete all alerts?"
        )

        if not answer:

            return

        self.database.clear_alerts()

        self.alert_count = 0

        self.update_statistics()

        for item in tree.get_children():

            tree.delete(
                item
            )

        self.update_dashboard()

        messagebox.showinfo(
            "History Cleared",
            "All security alerts have been deleted."
        )

    # =====================================================
    # EXPORT REPORT
    # =====================================================

    def export_report(self):

        try:

            filepath = (
                self.report_generator
                .generate_html_report()
            )

            messagebox.showinfo(
                "Report Generated",
                (
                    "Security report generated successfully.\n\n"
                    f"File:\n{filepath}"
                )
            )

            print(
                "Report generated:",
                filepath
            )

        except Exception as e:

            messagebox.showerror(
                "Report Error",
                str(e)
            )

    # =====================================================
    # CLOSE APPLICATION
    # =====================================================

    def close_application(self):

        try:

            self.packet_monitor.stop()

        except Exception:
            pass

        if self.dashboard_window is not None:

            try:

                self.dashboard_window.window.destroy()

            except Exception:
                pass

        self.root.destroy()


# =========================================================
# PROGRAM START
# =========================================================

if __name__ == "__main__":

    root = tk.Tk()

    app = NIDSApplication(
        root
    )

    root.mainloop()