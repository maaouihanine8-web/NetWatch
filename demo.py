"""Données de démonstration (sorties XML Nmap fictives) pour tester sans réseau réel."""
from scanner import parse_hosts, parse_ports

DISCOVERY_XML = """<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="A4:2B:B0:11:22:33" addrtype="mac" vendor="TP-Link"/>
    <hostnames><hostname name="routeur.local"/></hostnames></host>
  <host><status state="up"/><address addr="192.168.1.12" addrtype="ipv4"/>
    <address addr="3C:22:FB:44:55:66" addrtype="mac" vendor="Apple"/>
    <hostnames><hostname name="iphone-hanine"/></hostnames></host>
  <host><status state="up"/><address addr="192.168.1.20" addrtype="ipv4"/>
    <address addr="B8:27:EB:77:88:99" addrtype="mac" vendor="Raspberry Pi Foundation"/></host>
  <host><status state="up"/><address addr="192.168.1.34" addrtype="ipv4"/>
    <address addr="00:1A:2B:AA:BB:CC" addrtype="mac" vendor="Hikvision"/>
    <hostnames><hostname name="camera-salon"/></hostnames></host>
  <host><status state="up"/><address addr="192.168.1.50" addrtype="ipv4"/>
    <address addr="F0:DE:F1:12:34:56" addrtype="mac" vendor="Dell"/>
    <hostnames><hostname name="pc-bureau"/></hostnames></host>
</nmaprun>"""


def _ports_xml(*ports):
    items = "".join(
        f'<port protocol="tcp" portid="{p}"><state state="open"/>'
        f'<service name="{name}" product="{prod}"/></port>'
        for p, name, prod in ports
    )
    return f"<nmaprun><host><ports>{items}</ports></host></nmaprun>"


PORTS_XML = {
    "192.168.1.1": _ports_xml((53, "domain", "dnsmasq"), (80, "http", "TP-Link httpd"), (443, "https", "")),
    "192.168.1.12": _ports_xml(),
    "192.168.1.20": _ports_xml((22, "ssh", "OpenSSH 9.2"), (8080, "http-proxy", "Flask")),
    "192.168.1.34": _ports_xml((23, "telnet", "BusyBox telnetd"), (80, "http", "Hikvision"), (554, "rtsp", "")),
    "192.168.1.50": _ports_xml((135, "msrpc", "Microsoft Windows RPC"), (445, "microsoft-ds", ""),
                               (3389, "ms-wbt-server", "Microsoft Terminal Services")),
}


def demo_hosts() -> list[dict]:
    return parse_hosts(DISCOVERY_XML)


def demo_ports(ip: str) -> list[dict]:
    return parse_ports(PORTS_XML.get(ip, "<nmaprun/>"))
