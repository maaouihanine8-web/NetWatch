"""Scan réseau avec Nmap : découverte des appareils et scan des ports.

Les commandes Nmap sont lancées sans shell (liste d'arguments) et la cible est
validée : seuls les réseaux privés (RFC 1918) peuvent être scannés.
"""
import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET


class ScanError(Exception):
    """Erreur de validation ou d'exécution d'un scan."""


def validate_target(target: str) -> str:
    """Valide la cible : réseau privé, taille raisonnable. Retourne la cible normalisée."""
    try:
        network = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError as exc:
        raise ScanError(f"Cible invalide : {target!r}") from exc
    if not network.is_private:
        raise ScanError("Seuls les réseaux privés (192.168.x.x, 10.x.x.x, 172.16-31.x.x) peuvent être scannés.")
    if network.num_addresses > 1024:
        raise ScanError("Plage trop grande (maximum /22).")
    return str(network)


def parse_hosts(xml_text: str) -> list[dict]:
    """Extrait les appareils actifs (ip, mac, fabricant, nom d'hôte) d'une sortie XML Nmap."""
    hosts = []
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        info = {"ip": None, "mac": None, "vendor": None, "hostname": None}
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                info["ip"] = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                info["mac"] = addr.get("addr")
                info["vendor"] = addr.get("vendor")
        name = host.find("hostnames/hostname")
        if name is not None:
            info["hostname"] = name.get("name")
        if info["ip"]:
            hosts.append(info)
    return hosts


def parse_ports(xml_text: str) -> list[dict]:
    """Extrait les ports ouverts (port, protocole, service, produit) d'une sortie XML Nmap."""
    ports = []
    root = ET.fromstring(xml_text)
    for port in root.findall("host/ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port.find("service")
        product = ""
        if service is not None:
            product = " ".join(filter(None, [service.get("product"), service.get("version")]))
        ports.append({
            "port": int(port.get("portid")),
            "protocol": port.get("protocol"),
            "service": service.get("name") if service is not None else "inconnu",
            "product": product,
        })
    return sorted(ports, key=lambda p: p["port"])


def _run_nmap(args: list[str], timeout: int = 300) -> str:
    nmap = shutil.which("nmap")
    if nmap is None:
        raise ScanError("Nmap n'est pas installé (voir README), ou lancez l'application en mode démo.")
    try:
        result = subprocess.run([nmap, *args], capture_output=True, text=True, timeout=timeout, check=True)
    except subprocess.TimeoutExpired as exc:
        raise ScanError("Le scan a dépassé le délai autorisé.") from exc
    except subprocess.CalledProcessError as exc:
        raise ScanError(f"Nmap a échoué : {exc.stderr.strip()}") from exc
    return result.stdout


def discover_hosts(target: str) -> list[dict]:
    """Découvre les appareils connectés (ping scan). Les fabricants nécessitent les droits root/admin."""
    return parse_hosts(_run_nmap(["-sn", "-oX", "-", validate_target(target)]))


def scan_ports(ip: str) -> list[dict]:
    """Scanne les 100 ports les plus courants d'un appareil et identifie les services."""
    validate_target(ip)
    return parse_ports(_run_nmap(["-F", "--open", "-sV", "-oX", "-", ip]))
