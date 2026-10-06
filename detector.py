from collections import defaultdict, deque
import time


class IntrusionDetector:

    def __init__(self):

        # =================================================
        # TRACKING DATA
        # =================================================

        self.connections = defaultdict(deque)

        self.icmp_packets = defaultdict(deque)

        self.tcp_packets = defaultdict(deque)

        # =================================================
        # DETECTION SETTINGS
        # =================================================

        self.time_window = 10

        # Number of different TCP ports
        # required to trigger port scan detection
        self.port_threshold = 15

        # Number of TCP packets
        # allowed within the time window
        self.tcp_threshold = 50

        # Number of ICMP packets
        # allowed within the time window
        self.icmp_threshold = 30

        # Prevent the same alert from being
        # generated continuously
        self.alert_cooldown = 10

        self.last_alert = {}

    # =====================================================
    # MAIN ANALYSIS FUNCTION
    # =====================================================

    def analyze(self, packet):

        protocol = packet.get(
            "protocol",
            ""
        )

        source_ip = packet.get(
            "source",
            "Unknown"
        )

        current_time = time.time()

        # =================================================
        # TCP ANALYSIS
        # =================================================

        if protocol == "TCP":

            return self.analyze_tcp(
                packet,
                source_ip,
                current_time
            )

        # =================================================
        # ICMP ANALYSIS
        # =================================================

        elif protocol == "ICMP":

            return self.analyze_icmp(
                source_ip,
                current_time
            )

        return None

    # =====================================================
    # TCP ANALYSIS
    # =====================================================

    def analyze_tcp(
        self,
        packet,
        source_ip,
        current_time
    ):

        destination_port = packet.get(
            "port",
            None
        )

        # -------------------------------------------------
        # Store TCP connection
        # -------------------------------------------------

        self.connections[source_ip].append(
            (
                current_time,
                destination_port
            )
        )

        # -------------------------------------------------
        # Remove old entries
        # -------------------------------------------------

        while self.connections[source_ip]:

            old_time = (
                self.connections[source_ip][0][0]
            )

            if (
                current_time - old_time
                > self.time_window
            ):

                self.connections[
                    source_ip
                ].popleft()

            else:

                break

        # =================================================
        # PORT SCAN DETECTION
        # =================================================

        ports = set()

        for timestamp, port in self.connections[source_ip]:

            if port is not None:

                ports.add(port)

        if len(ports) >= self.port_threshold:

            if self.can_alert(
                source_ip,
                "Possible Port Scan",
                current_time
            ):

                return {
                    "type": "Possible Port Scan",

                    "source": source_ip,

                    "ports": len(ports),

                    "risk": "HIGH",

                    "message": (
                        f"{source_ip} contacted "
                        f"{len(ports)} different TCP ports "
                        f"within {self.time_window} seconds."
                    )
                }

        # =================================================
        # TCP BURST DETECTION
        # =================================================

        self.tcp_packets[source_ip].append(
            current_time
        )

        while self.tcp_packets[source_ip]:

            old_time = (
                self.tcp_packets[source_ip][0]
            )

            if (
                current_time - old_time
                > self.time_window
            ):

                self.tcp_packets[
                    source_ip
                ].popleft()

            else:

                break

        tcp_count = len(
            self.tcp_packets[source_ip]
        )

        if tcp_count >= self.tcp_threshold:

            if self.can_alert(
                source_ip,
                "TCP Connection Burst",
                current_time
            ):

                return {
                    "type": "TCP Connection Burst",

                    "source": source_ip,

                    "count": tcp_count,

                    "risk": "MEDIUM",

                    "message": (
                        f"{source_ip} generated "
                        f"{tcp_count} TCP packets "
                        f"within {self.time_window} seconds."
                    )
                }

        return None

    # =====================================================
    # ICMP ANALYSIS
    # =====================================================

    def analyze_icmp(
        self,
        source_ip,
        current_time
    ):

        self.icmp_packets[source_ip].append(
            current_time
        )

        # -------------------------------------------------
        # Remove old packets
        # -------------------------------------------------

        while self.icmp_packets[source_ip]:

            old_time = (
                self.icmp_packets[source_ip][0]
            )

            if (
                current_time - old_time
                > self.time_window
            ):

                self.icmp_packets[
                    source_ip
                ].popleft()

            else:

                break

        icmp_count = len(
            self.icmp_packets[source_ip]
        )

        # =================================================
        # ICMP BURST DETECTION
        # =================================================

        if icmp_count >= self.icmp_threshold:

            if self.can_alert(
                source_ip,
                "ICMP Traffic Burst",
                current_time
            ):

                return {
                    "type": "ICMP Traffic Burst",

                    "source": source_ip,

                    "count": icmp_count,

                    "risk": "MEDIUM",

                    "message": (
                        f"{source_ip} generated "
                        f"{icmp_count} ICMP packets "
                        f"within {self.time_window} seconds."
                    )
                }

        return None

    # =====================================================
    # ALERT COOLDOWN
    # =====================================================

    def can_alert(
        self,
        source_ip,
        alert_type,
        current_time
    ):

        key = (
            source_ip,
            alert_type
        )

        last_time = self.last_alert.get(
            key,
            0
        )

        if (
            current_time - last_time
            < self.alert_cooldown
        ):

            return False

        self.last_alert[key] = current_time

        return True