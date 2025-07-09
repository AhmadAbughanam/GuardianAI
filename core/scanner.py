# core/scanner.py

import scapy.all as scapy
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common ports to scan for each device (can be expanded)
COMMON_PORTS = [
    20,
    21,  # FTP (data + control)
    22,  # SSH
    23,  # Telnet
    25,  # SMTP
    53,  # DNS
    67,
    68,  # DHCP
    69,  # TFTP
    80,  # HTTP
    110,  # POP3
    111,  # RPCbind
    123,  # NTP
    135,
    137,
    138,
    139,
    445,  # Windows SMB, NetBIOS
    143,  # IMAP
    161,
    162,  # SNMP
    179,  # BGP
    389,  # LDAP
    443,  # HTTPS
    465,  # SMTPS
    514,  # Syslog
    587,  # SMTP (submission)
    631,  # IPP (Printer)
    993,  # IMAPS
    995,  # POP3S
    1080,  # SOCKS proxy
    1433,
    1434,  # MSSQL
    1521,  # Oracle DB
    1723,  # PPTP VPN
    1883,  # MQTT
    1900,  # SSDP (UPnP)
    2049,  # NFS
    3306,  # MySQL
    3389,  # RDP
    5060,  # SIP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8000,
    8080,
    8443,  # HTTP alternatives
    9000,
    9200,  # Web servers / Elasticsearch]
]


class DeviceScanner:
    def __init__(self, subnet: str = None, ports=None, max_workers=100):
        """
        :param subnet: subnet to scan in CIDR format e.g. '192.168.1.0/24'
                       If None, auto-detect subnet.
        :param ports: list of TCP ports to scan
        :param max_workers: concurrency for port scanning
        """
        self.subnet = subnet or self._get_default_subnet()
        self.ports = ports or COMMON_PORTS
        self.max_workers = max_workers

    def _get_default_subnet(self):
        # Try to auto-detect local subnet via default gateway interface
        gateways = scapy.conf.route.routes
        for gw in gateways:
            if gw[2] != "0.0.0.0":  # skip default route
                iface = gw[3]
                if iface:
                    addrs = scapy.get_if_addr(iface)
                    if addrs:
                        ip_parts = addrs.split(".")[:3]
                        return ".".join(ip_parts) + ".0/24"
        # Fallback to common local subnet
        return "192.168.1.0/24"

    def scan_network(self):
        """
        Performs an ARP scan to discover devices on the subnet.
        Returns a list of dicts: [{ip, mac, hostname}]
        """
        arp_request = scapy.ARP(pdst=self.subnet)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]

        devices = []
        for sent, received in answered_list:
            ip = received.psrc
            mac = received.hwsrc
            hostname = self._get_hostname(ip)
            devices.append({"ip": ip, "mac": mac, "hostname": hostname})
        return devices

    def _get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return None

    def _scan_port(self, ip, port, timeout=1):
        """
        Returns True if TCP port is open on given IP, else False
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def scan_ports(self, ip):
        """
        Scan defined ports on a single IP address.
        Returns a dict {port: bool (open/closed)}
        """
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._scan_port, ip, port): port for port in self.ports
            }
            for future in as_completed(futures):
                port = futures[future]
                if future.result():
                    open_ports.append(port)
        return open_ports

    def full_scan(self):
        """
        Scans the entire subnet for devices and their open ports.
        Returns a list of dicts with device info and open ports:
        [
          {
            'ip': str,
            'mac': str,
            'hostname': str or None,
            'open_ports': [int, int, ...]
          },
          ...
        ]
        """
        devices = self.scan_network()
        for device in devices:
            device["open_ports"] = self.scan_ports(device["ip"])
        return devices


if __name__ == "__main__":
    scanner = DeviceScanner()
    print("Starting full network scan...")
    results = scanner.full_scan()
    for device in results:
        print(
            f"IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname']}"
        )
        print(f"Open Ports: {device['open_ports']}\n")
