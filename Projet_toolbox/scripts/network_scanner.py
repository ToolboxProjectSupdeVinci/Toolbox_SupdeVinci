import scapy.all as scapy

def scan_network(ip: str):
    """Returns a list of dictionaries containing IP and MAC address pairs of clients on the network."""
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_packet = broadcast_packet/arp_packet
    answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
    client_list = []

    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)

    return client_list

def format_scan_results(scan_list):
    """Formats the scan results for reporting."""
    report_content = "IP\t\t\tMAC\n----------------------------------------\n"
    for client in scan_list:
        report_content += f"{client['ip']}\t\t{client['mac']}\n"
    return report_content
