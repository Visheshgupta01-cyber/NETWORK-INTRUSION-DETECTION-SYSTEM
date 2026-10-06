from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP
from datetime import datetime


class PacketMonitor:

    def __init__(self, callback):
        self.callback = callback
        self.sniffer = None

    def process_packet(self, packet):

        try:

            # Ignore packets without IP
            if IP not in packet:
                return

            source = packet[IP].src
            destination = packet[IP].dst

            timestamp = datetime.now().strftime("%H:%M:%S")

            protocol = "IP"
            port = "-"

            if TCP in packet:

                protocol = "TCP"
                port = packet[TCP].dport

            elif UDP in packet:

                protocol = "UDP"
                port = packet[UDP].dport

            elif ICMP in packet:

                protocol = "ICMP"
                port = "-"

            packet_data = {
                "time": timestamp,
                "source": source,
                "destination": destination,
                "protocol": protocol,
                "port": port
            }

            # Send packet to GUI
            self.callback(packet_data)

        except Exception as e:

            print("Packet processing error:", e)

    def start(self):

        if self.sniffer is not None:
            return

        self.sniffer = AsyncSniffer(
            filter="ip",
            prn=self.process_packet,
            store=False
        )

        self.sniffer.start()

        print("Packet monitoring started.")

    def stop(self):

        if self.sniffer is None:
            return

        try:
            self.sniffer.stop()
            print("Packet monitoring stopped.")

        except Exception as e:

            print("Error stopping sniffer:", e)

        finally:

            self.sniffer = None