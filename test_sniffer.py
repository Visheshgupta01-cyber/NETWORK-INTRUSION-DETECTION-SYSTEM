from scapy.all import sniff


print("Starting packet capture...")
print("Press CTRL+C to stop.\n")

sniff(
    filter="ip",
    prn=lambda packet: packet.summary(),
    store=False
)
