"""Règles de détection : ports sensibles ou potentiellement dangereux."""

SEVERITY_ORDER = {"info": 0, "faible": 1, "moyen": 2, "élevé": 3}

# port -> (gravité, explication)
SENSITIVE_PORTS = {
    21: ("moyen", "FTP : transfert en clair, identifiants interceptables"),
    22: ("faible", "SSH : vérifier l'authentification par clé et désactiver le mot de passe"),
    23: ("élevé", "Telnet : protocole non chiffré, à désactiver"),
    25: ("faible", "SMTP : vérifier que le relais ouvert est désactivé"),
    80: ("faible", "HTTP : trafic non chiffré, préférer HTTPS"),
    110: ("moyen", "POP3 : messagerie en clair"),
    135: ("élevé", "RPC Windows : exposition de services système"),
    139: ("élevé", "NetBIOS : fuite d'informations, souvent exploité"),
    143: ("moyen", "IMAP : messagerie en clair"),
    445: ("élevé", "SMB : cible fréquente de ransomwares et de vers"),
    1433: ("élevé", "Microsoft SQL Server exposé"),
    3306: ("élevé", "MySQL exposé sur le réseau"),
    3389: ("élevé", "RDP : bureau à distance, cible fréquente d'attaques par force brute"),
    5432: ("moyen", "PostgreSQL exposé sur le réseau"),
    5900: ("élevé", "VNC : contrôle à distance souvent mal protégé"),
    8080: ("faible", "HTTP alternatif : interface d'administration possible"),
}


def evaluate(ports: list[dict]) -> list[dict]:
    """Retourne une alerte par port sensible parmi les ports ouverts."""
    alerts = []
    for p in ports:
        rule = SENSITIVE_PORTS.get(p["port"])
        if rule:
            severity, reason = rule
            alerts.append({
                "kind": "port",
                "severity": severity,
                "message": f"Port {p['port']}/{p['protocol']} ouvert : {reason}",
            })
    return alerts


def highest_severity(severities) -> str:
    """Gravité maximale d'une liste (« info » si vide)."""
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0), default="info")
